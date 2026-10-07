import os
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("VPNGATE_DATA_DIR", tempfile.mkdtemp(prefix="aimili-dns-"))
sys.path.insert(0, str(ROOT))
import proxy_server as ps


def _response(ttl=120, ip=(1, 2, 3, 4), tx=b"\x12\x34"):
    question = b"\x06google\x03com\x00\x00\x01\x00\x01"
    answer = b"\xc0\x0c\x00\x01\x00\x01" + int(ttl).to_bytes(4, "big") + b"\x00\x04" + bytes(ip)
    header = tx + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    return header + question + answer


def test_parse_ttl():
    ip, ttl = ps._parse_dns_a(_response(), b"\x12\x34", 1)
    assert (ip, ttl) == ("1.2.3.4", 120.0)
    assert ps._parse_dns_a(_response(tx=b"\x00\x01"), b"\x12\x34", 1)[0] is None


def test_direct_is_not_tun0():
    os.environ.pop("ACTIVE_TUNNEL_IFACE", None)
    iface_file = Path(os.environ["VPNGATE_DATA_DIR"]) / "active_iface.txt"
    iface_file.parent.mkdir(parents=True, exist_ok=True)
    iface_file.write_text("", encoding="utf-8")
    ps._iface_cache_token = None
    ps._iface_cache_value = "tun0"
    assert ps.get_active_interface() == ""
    iface_file.write_text("vpn_aimili\n", encoding="utf-8")
    assert ps.get_active_interface() == "vpn_aimili"
    iface_file.write_text("direct\n", encoding="utf-8")
    assert ps.get_active_interface() == ""


def test_singleflight_and_scope():
    os.environ.pop("ACTIVE_TUNNEL_IFACE", None)
    ps.DNS_CACHE.clear()
    ps._DNS_FLIGHTS.clear()
    calls = []

    def slow_query(host, qtype, server, timeout, iface):
        calls.append((server, iface))
        time.sleep(0.05)
        if server == "8.8.8.8":
            return "9.9.9.9", 45
        time.sleep(0.2)
        return "8.8.4.4", 45

    ps._dns_udp_query = slow_query
    results = []

    def worker():
        results.append(ps.resolve_dns_over_active_tunnel("google.com", iface="vpn_aimili", timeout=1.0))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == ["9.9.9.9"] * 8
    assert sum(1 for server, _iface in calls if server == "8.8.8.8") == 1
    assert ps.resolve_dns_over_active_tunnel("google.com", iface="vpn_aimili") == "9.9.9.9"
    assert sum(1 for server, _iface in calls if server == "8.8.8.8") == 1

    system = []
    ps._system_dns_ipv4 = lambda host, timeout: system.append(host) or "34.4.110.244"
    assert ps.resolve_dns_over_active_tunnel("google.com", iface="") == "34.4.110.244"
    assert system == ["google.com"]


if __name__ == "__main__":
    test_parse_ttl()
    test_direct_is_not_tun0()
    test_singleflight_and_scope()
    print("dns tests ok")
