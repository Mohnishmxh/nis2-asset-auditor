import ipaddress
import nmap
from typing import List, Dict

def validate_private_target(target: str) -> bool:
    """
    Safety Guardrail: Ensures scanning is strictly restricted to loopback
    or RFC 1918 private internal networks (NIS2 internal asset auditing).
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
        return net.is_private or net.is_loopback
    except ValueError:
        return False

def discover_services(target: str, ports: str = "22,80,443,3306,5432,8000,8080") -> List[Dict]:
    """Runs a local service version audit using Nmap."""
    if not validate_private_target(target):
        raise PermissionError(
            f"Scope Violation: '{target}' is outside authorized private/loopback RFC 1918 space."
        )

    nm = nmap.PortScanner()
    # -sV: Probe open ports to determine service/version info
    # -T4: Aggressive timing suitable for local lab networks
    nm.scan(hosts=target, ports=ports, arguments="-sV -T4")

    assets = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                svc = nm[host][proto][port]
                if svc.get("state") == "open":
                    assets.append({
                        "host": host,
                        "port": port,
                        "protocol": proto,
                        "service": svc.get("name", "unknown"),
                        "product": svc.get("product", "").strip(),
                        "version": svc.get("version", "").strip(),
                        "cpe": svc.get("cpe", "")
                    })
    return assets