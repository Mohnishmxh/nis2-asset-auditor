"""RFC 1918 scope guardrails and resilient service discovery."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import re
import socket
import ssl
from typing import Any, Callable, Dict, List, Optional, Tuple

import nmap

from src.models import ScopeValidationResult

MAX_AUDIT_HOSTS = 1024

ALLOWED_V4_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)

ALLOWED_V6_NETWORKS = (
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
)

SCAN_PROFILES: Dict[str, Dict[str, str]] = {
    "quick": {
        "id": "quick",
        "name": "Quick Posture Check",
        "ports": "21,22,23,25,53,80,443,3306,5432,6379,8000,8080,8443",
        "description": "Fast audit across essential web, remote access, and data-store ports.",
    },
    "web": {
        "id": "web",
        "name": "Web & API Stack",
        "ports": "80,443,3000,5000,8000,8080,8443,8888,9000",
        "description": "Targets reverse proxies, web servers, and internal REST/GraphQL endpoints.",
    },
    "database": {
        "id": "database",
        "name": "Databases & Caches",
        "ports": "1433,1521,3306,5432,6379,9200,11211,27017",
        "description": "Detects unencrypted or exposed SQL/NoSQL databases and in-memory caches.",
    },
    "infra": {
        "id": "infra",
        "name": "Infrastructure & Admin",
        "ports": "21,22,23,135,139,445,2375,2376,3389,5900,9090,9100",
        "description": "Audits SSH, RDP, SMB, legacy plaintext services, and exposed Docker/metrics APIs.",
    },
    "comprehensive": {
        "id": "comprehensive",
        "name": "Comprehensive Internal",
        "ports": "21,22,23,25,53,80,110,135,139,143,443,445,1433,2375,2376,3000,3306,3389,5000,5432,5900,6379,8000,8080,8443,9000,9200,27017",
        "description": "Broad internal surface check across applications, admin services, and storage.",
    },
}

TLS_PORTS = {443, 465, 636, 993, 995, 2376, 8443}

PORT_SERVICE_HINTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    1433: "ms-sql-s",
    2375: "docker",
    2376: "docker-s",
    3000: "http",
    3306: "mysql",
    3389: "ms-wbt-server",
    5000: "http",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http",
    8080: "http",
    8443: "https",
    9000: "http",
    9090: "http",
    9200: "elasticsearch",
    11211: "memcache",
    27017: "mongodb",
}

_PORT_TOKEN_RE = re.compile(r"^(?:[TU]:)?\d+(?:-\d+)?$")
_CPE22_RE = re.compile(r"^cpe:/([aho]):([^:]+):([^:]+)(?::([^:]*))?")
_NMAP_SEARCH_PATHS = (
    "nmap",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/opt/homebrew/bin/nmap",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
)

ProgressCallback = Callable[[str, str, int], None]


def _classify_network(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> Tuple[bool, str]:
    """Check whether an IP network strictly belongs to RFC 1918, ULA, or loopback."""
    if net.is_multicast or net.is_unspecified:
        return False, "Multicast or unspecified network rejected"

    if isinstance(net, ipaddress.IPv4Network):
        if net.overlaps(ipaddress.ip_network("127.0.0.0/8")) and net.subnet_of(
            ipaddress.ip_network("127.0.0.0/8")
        ):
            return True, "Loopback (127.0.0.0/8)"
        for allowed in ALLOWED_V4_NETWORKS[:3]:
            if net.subnet_of(allowed):
                return True, f"RFC 1918 Private ({allowed})"
        return False, "Public, link-local, or non-RFC1918 IPv4 range rejected"

    for allowed in ALLOWED_V6_NETWORKS:
        if net.subnet_of(allowed):
            label = "IPv6 Loopback (::1)" if str(allowed) == "::1/128" else "RFC 4193 IPv6 ULA"
            return True, label
    return False, "Non-private IPv6 range rejected"


def validate_scope_details(target: str, max_hosts: int = MAX_AUDIT_HOSTS) -> ScopeValidationResult:
    """
    Validate one or more comma-separated targets (IP, CIDR, or 'localhost')
    against strict internal-only scope guardrails.
    """
    raw_target = (target or "").strip()
    if not raw_target:
        return ScopeValidationResult(valid=False, reason="Target cannot be empty.")

    if re.search(r"[;&|`$\s]", raw_target.replace(" ", "")):
        return ScopeValidationResult(
            valid=False, reason="Target contains unsupported characters."
        )

    tokens = [t.strip() for t in raw_target.split(",") if t.strip()]
    if not tokens:
        return ScopeValidationResult(valid=False, reason="No valid target specified.")

    normalized: List[str] = []
    classes: List[str] = []
    total_hosts = 0

    for token in tokens:
        candidate = "127.0.0.1" if token.lower() == "localhost" else token
        try:
            net = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            return ScopeValidationResult(
                valid=False,
                reason=f"'{token}' is not a valid IPv4/IPv6 address, CIDR range, or 'localhost'.",
            )

        allowed, net_class = _classify_network(net)
        if not allowed:
            return ScopeValidationResult(
                valid=False,
                reason=f"Scope Violation: '{token}' is outside authorized RFC 1918 / loopback space ({net_class}).",
            )

        total_hosts += int(net.num_addresses)
        if total_hosts > max_hosts:
            return ScopeValidationResult(
                valid=False,
                host_count=total_hosts,
                reason=(
                    f"Subnet guardrail: '{token}' expands to {total_hosts} hosts, "
                    f"exceeding the safe per-audit cap of {max_hosts} hosts."
                ),
            )

        normalized.append(str(net.network_address) if net.num_addresses == 1 else str(net))
        if net_class not in classes:
            classes.append(net_class)

    return ScopeValidationResult(
        valid=True,
        normalized_targets=normalized,
        host_count=total_hosts,
        network_classes=classes,
        reason="Verified RFC 1918 / Loopback internal scope.",
    )


def validate_private_target(target: str) -> bool:
    """
    Safety Guardrail: Ensures scanning is strictly restricted to loopback
    or RFC 1918 private internal networks (NIS2 internal asset auditing).
    """
    return validate_scope_details(target).valid


def validate_ports_spec(ports: str) -> List[int]:
    """Validate an Nmap-style port specification and return sorted concrete TCP ports."""
    raw = (ports or "").strip()
    if not raw:
        raise ValueError("Port specification cannot be empty.")

    tokens = [tok.strip() for tok in raw.split(",") if tok.strip()]
    if not tokens:
        raise ValueError("Port specification contains no ports.")

    resolved_ports: List[int] = []
    seen = set()

    for tok in tokens:
        if not _PORT_TOKEN_RE.match(tok):
            raise ValueError(f"Invalid port token '{tok}'. Use comma-separated ports or ranges (e.g. 22,80,8000-8010).")
        body = tok[2:] if tok[:2] in ("T:", "U:") else tok
        if "-" in body:
            start_s, end_s = body.split("-", 1)
            start_p, end_p = int(start_s), int(end_s)
            if start_p < 1 or end_p > 65535 or start_p > end_p:
                raise ValueError(f"Port range '{tok}' must be within 1-65535.")
            if end_p - start_p > 2048:
                raise ValueError(f"Port range '{tok}' is too large (max 2048 ports per range).")
            for p in range(start_p, end_p + 1):
                if p not in seen:
                    seen.add(p)
                    resolved_ports.append(p)
        else:
            p = int(body)
            if p < 1 or p > 65535:
                raise ValueError(f"Port '{p}' must be within 1-65535.")
            if p not in seen:
                seen.add(p)
                resolved_ports.append(p)

    return resolved_ports


def normalize_cpe_to_23(cpe: str) -> str:
    """Convert an Nmap CPE 2.2 string (cpe:/a:vendor:product:ver) to CPE 2.3 format."""
    if not cpe:
        return ""
    if cpe.startswith("cpe:2.3:"):
        return cpe
    match = _CPE22_RE.match(cpe.strip())
    if not match:
        return cpe.strip()
    part, vendor, product, version = match.groups()
    ver_part = version if version else "*"
    return f"cpe:2.3:{part}:{vendor}:{product}:{ver_part}:*:*:*:*:*:*:*"


def _classify_exposure(host: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(host)
        return "loopback" if ip_obj.is_loopback else "internal-lan"
    except ValueError:
        return "internal-lan"


def _is_encrypted_service(service_name: str, port: int, tunnel: str = "") -> bool:
    svc = (service_name or "").lower()
    if tunnel.lower() == "ssl" or port in TLS_PORTS:
        return True
    return svc in {"ssh", "https", "ssl", "tls", "imaps", "pop3s", "smtps", "ldaps"}


def _parse_banner_product_version(service: str, banner: str) -> Tuple[str, str]:
    """Heuristically extract product and version from a raw socket banner."""
    if not banner:
        return "", ""

    ssh_match = re.search(r"SSH-[\d.]+-OpenSSH[_-]([^\s\r\n]+)", banner, re.IGNORECASE)
    if ssh_match:
        return "OpenSSH", ssh_match.group(1)

    server_match = re.search(r"^Server:\s*([^\r\n]+)", banner, re.IGNORECASE | re.MULTILINE)
    if server_match:
        server_hdr = server_match.group(1).strip()
        prod_ver = re.match(r"([A-Za-z0-9._-]+)(?:/([^\s(;]+))?", server_hdr)
        if prod_ver:
            prod = prod_ver.group(1)
            if prod.lower() == "apache":
                prod = "Apache httpd"
            elif prod.lower() == "simplehttp":
                prod = "SimpleHTTPServer"
            return prod, prod_ver.group(2) or ""

    redis_match = re.search(r"redis_version:([0-9.]+)", banner)
    if redis_match:
        return "Redis", redis_match.group(1)

    ftp_match = re.search(r"220[- ].*?(vsFTPd|ProFTPD|FileZilla Server)\s+([0-9][^\s)]*)", banner, re.IGNORECASE)
    if ftp_match:
        return ftp_match.group(1), ftp_match.group(2)

    if service == "mysql" and len(banner) > 5:
        ver_match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+[^\x00\s]*)", banner)
        if ver_match:
            return "MySQL", ver_match.group(1)

    return "", ""


def _probe_single_socket(host: str, port: int, timeout: float = 1.2) -> Optional[Dict[str, Any]]:
    """Probe a single TCP port using stdlib sockets and grab an initial banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            service_hint = PORT_SERVICE_HINTS.get(port, "unknown")
            banner_bytes = b""
            tls_detected = port in TLS_PORTS

            if port in TLS_PORTS:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        ssock.settimeout(timeout)
                        ssock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                        banner_bytes = ssock.recv(1024)
                except Exception:
                    tls_detected = True
            else:
                if port in {80, 3000, 5000, 8000, 8080, 8888, 9000, 9090, 9200, 2375}:
                    sock.settimeout(timeout)
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    try:
                        banner_bytes = sock.recv(1024)
                    except socket.timeout:
                        banner_bytes = b""
                elif port == 6379:
                    sock.settimeout(timeout)
                    sock.sendall(b"INFO server\r\n")
                    try:
                        banner_bytes = sock.recv(1024)
                    except socket.timeout:
                        banner_bytes = b""
                else:
                    # Try server-speaks-first banner briefly (SSH/FTP/SMTP), then HTTP GetRequest probe
                    sock.settimeout(0.35)
                    try:
                        banner_bytes = sock.recv(1024)
                    except socket.timeout:
                        banner_bytes = b""
                    if not banner_bytes:
                        try:
                            sock.settimeout(timeout)
                            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                            banner_bytes = sock.recv(1024)
                        except OSError:
                            banner_bytes = b""

            banner = banner_bytes.decode("utf-8", errors="replace").strip()
            if service_hint == "unknown" and banner.startswith("HTTP/"):
                service_hint = "http"
            product, version = _parse_banner_product_version(service_hint, banner)
            return {
                "host": host,
                "hostname": "localhost" if host == "127.0.0.1" else "",
                "port": port,
                "protocol": "tcp",
                "service": service_hint,
                "product": product,
                "version": version,
                "cpe": "",
                "extrainfo": "socket-banner-probe",
                "banner": banner[:240],
                "encrypted": _is_encrypted_service(service_hint, port, "ssl" if tls_detected else ""),
                "exposure": _classify_exposure(host),
            }
    except OSError:
        return None


def _expand_hosts_for_fallback(targets: List[str]) -> List[str]:
    hosts: List[str] = []
    for item in targets:
        net = ipaddress.ip_network(item, strict=False)
        if net.num_addresses == 1:
            hosts.append(str(net.network_address))
        else:
            for ip in net.hosts():
                hosts.append(str(ip))
                if len(hosts) >= MAX_AUDIT_HOSTS:
                    break
    return hosts


def discover_services_socket_fallback(
    normalized_targets: List[str],
    port_list: List[int],
    on_progress: Optional[ProgressCallback] = None,
) -> List[Dict[str, Any]]:
    """Pure-Python TCP connect & banner fallback when Nmap is unavailable or blocked."""
    hosts = _expand_hosts_for_fallback(normalized_targets)
    tasks = [(h, p) for h in hosts for p in port_list]
    assets: List[Dict[str, Any]] = []

    if on_progress:
        on_progress("discovery", f"Running Python socket fallback across {len(hosts)} host(s)...", 35)

    with ThreadPoolExecutor(max_workers=min(32, max(1, len(tasks)))) as pool:
        futures = {pool.submit(_probe_single_socket, h, p): (h, p) for h, p in tasks}
        for future in as_completed(futures):
            res = future.result()
            if res is not None:
                assets.append(res)

    assets.sort(key=lambda a: (a["host"], a["port"]))
    return assets


def discover_services_with_meta(
    target: str,
    ports: str = "22,80,443,3306,5432,8000,8080",
    on_progress: Optional[ProgressCallback] = None,
    allow_socket_fallback: bool = True,
) -> Tuple[List[Dict[str, Any]], str]:
    """
    Run service version audit against validated private targets.
    Returns (assets, engine_used) where engine_used is 'nmap' or 'socket-fallback'.
    """
    scope = validate_scope_details(target)
    if not scope.valid:
        raise PermissionError(scope.reason)

    port_list = validate_ports_spec(ports)
    nmap_target = " ".join(scope.normalized_targets)
    port_arg = ",".join(str(p) for p in port_list)

    if on_progress:
        on_progress(
            "scope",
            f"Verified RFC 1918 / Loopback scope ({scope.host_count} host(s), {len(port_list)} port(s))",
            15,
        )

    try:
        if on_progress:
            on_progress("discovery", f"Executing Nmap service/version probe (-sV) on {target}...", 30)

        nm = nmap.PortScanner(nmap_search_path=_NMAP_SEARCH_PATHS)
        nm.scan(hosts=nmap_target, ports=port_arg, arguments="-sV --version-intensity 5 -T4")

        assets: List[Dict[str, Any]] = []
        for host in nm.all_hosts():
            hostname = ""
            try:
                hostnames = nm[host].hostnames()
                if hostnames:
                    hostname = hostnames[0].get("name", "")
            except Exception:
                hostname = ""

            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    svc = nm[host][proto][port]
                    if svc.get("state") == "open":
                        service_name = svc.get("name", "unknown") or "unknown"
                        tunnel = svc.get("tunnel", "") or ""
                        cpe_raw = svc.get("cpe", "") or ""
                        assets.append({
                            "host": host,
                            "hostname": hostname,
                            "port": int(port),
                            "protocol": proto,
                            "service": service_name,
                            "product": (svc.get("product") or "").strip(),
                            "version": (svc.get("version") or "").strip(),
                            "cpe": normalize_cpe_to_23(cpe_raw),
                            "extrainfo": (svc.get("extrainfo") or "").strip(),
                            "banner": "",
                            "encrypted": _is_encrypted_service(service_name, int(port), tunnel),
                            "exposure": _classify_exposure(host),
                        })
        return assets, "nmap"

    except nmap.PortScannerError as exc:
        if not allow_socket_fallback:
            raise RuntimeError(f"Nmap scan failed: {exc}") from exc
        if on_progress:
            on_progress(
                "discovery",
                f"Nmap unavailable ({exc}); switching to pure-Python banner probe fallback...",
                35,
            )
        assets = discover_services_socket_fallback(
            scope.normalized_targets, port_list, on_progress=on_progress
        )
        return assets, "socket-fallback"


def discover_services(
    target: str,
    ports: str = "22,80,443,3306,5432,8000,8080",
    on_progress: Optional[ProgressCallback] = None,
) -> List[Dict[str, Any]]:
    """Run a local service version audit using Nmap (with socket banner fallback)."""
    assets, _ = discover_services_with_meta(target, ports=ports, on_progress=on_progress)
    return assets
