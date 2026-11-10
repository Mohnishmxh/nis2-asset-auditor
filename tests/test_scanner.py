"""Unit tests for RFC 1918 scope guardrails, port validation, and scanner fallback."""

import socket
import threading
from unittest.mock import patch

import nmap
import pytest

from src.scanner import (
    discover_services_with_meta,
    normalize_cpe_to_23,
    validate_ports_spec,
    validate_private_target,
    validate_scope_details,
)


def test_validate_private_targets_allows_rfc1918_and_loopback():
    for target in (
        "127.0.0.1",
        "localhost",
        "10.0.0.5",
        "172.16.4.0/24",
        "192.168.1.0/24",
        "::1",
        "fd00::/120",
        "127.0.0.1,192.168.1.10",
    ):
        assert validate_private_target(target), f"Expected valid target: {target}"


def test_validate_private_targets_blocks_public_and_unsafe_ranges():
    for target in (
        "",
        "8.8.8.8",
        "1.1.1.1/24",
        "0.0.0.0",
        "224.0.0.1",
        "169.254.169.254",
        "10.0.0.0/8",  # exceeds MAX_AUDIT_HOSTS guardrail
        "127.0.0.1;rm -rf /",
        "example.com",
    ):
        res = validate_scope_details(target)
        assert not res.valid, f"Expected rejected target: {target}"


def test_validate_ports_spec():
    assert validate_ports_spec("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]
    assert validate_ports_spec("T:443,80") == [443, 80]

    for bad in ("", "0", "65536", "100-50", "80;id", "abc"):
        with pytest.raises(ValueError):
            validate_ports_spec(bad)


def test_normalize_cpe_to_23():
    assert (
        normalize_cpe_to_23("cpe:/a:openbsd:openssh:8.9p1")
        == "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"
    )
    assert (
        normalize_cpe_to_23("cpe:2.3:a:f5:nginx:1.26.2:*:*:*:*:*:*:*")
        == "cpe:2.3:a:f5:nginx:1.26.2:*:*:*:*:*:*:*"
    )


def test_socket_fallback_discovers_local_ephemeral_banner():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def _serve_once():
        conn, _ = server.accept()
        with conn:
            conn.recv(256)
            conn.sendall(b"HTTP/1.0 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n")

    t = threading.Thread(target=_serve_once, daemon=True)
    t.start()

    try:
        with patch("src.scanner.nmap.PortScanner", side_effect=nmap.PortScannerError("no nmap")):
            assets, engine = discover_services_with_meta("127.0.0.1", str(port))
        assert engine == "socket-fallback"
        assert len(assets) == 1
        assert assets[0]["port"] == port
        assert assets[0]["product"] == "Apache httpd"
        assert assets[0]["version"] == "2.4.49"
    finally:
        server.close()
        t.join(timeout=2)
