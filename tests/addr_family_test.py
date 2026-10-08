"""IPv4-mapped addresses must match a manually allowed IPv4, and UDP must too."""
import tempfile
from pathlib import Path

from resource_sharing import ResourceShareManager
import proxy_server


def test_manual_ipv4_accepts_mapped_form():
    cidrs = ResourceShareManager.normalize_cidrs("67.10.84.82")
    assert cidrs == ["67.10.84.82/32"]
    assert ResourceShareManager._cidr_allowed("::ffff:67.10.84.82", cidrs)
    assert ResourceShareManager._cidr_allowed("67.10.84.82", cidrs)
    assert not ResourceShareManager._cidr_allowed("2001:db8::1", cidrs)
    # A different-family entry before the manual /32 must not hide it.
    assert ResourceShareManager._cidr_allowed("67.10.84.82", ["::/0", "67.10.84.82/32"])
    assert ResourceShareManager._sources_allowed(
        ["2001:db8::9", "::ffff:67.10.84.82"],
        ["67.10.84.82/32"],
    ) == "67.10.84.82"


def test_forwarded_header_cannot_hide_the_tcp_peer():
    class Headers(dict):
        def get(self, key, default=None):
            return super().get(key, default)

    headers = Headers({"X-Forwarded-For": "2001:db8::9", "X-Real-IP": "1.2.3.4"})
    # Direct peer is the manually allowed address. The header is not trusted.
    assert ResourceShareManager.client_ips(headers, ("::ffff:67.10.84.82", 443)) == ["67.10.84.82"]
    # Nginx on loopback: the real client header is the source, still unwrapped.
    headers["X-Real-IP"] = "::ffff:67.10.84.82"
    assert ResourceShareManager.client_ips(headers, ("127.0.0.1", 8443))[0] == "127.0.0.1"
    assert "67.10.84.82" in ResourceShareManager.client_ips(headers, ("127.0.0.1", 8443))


def test_proxy_allow_manual_ip_after_other_family():
    old = proxy_server.os.environ.get("LOCAL_PROXY_ALLOW")
    proxy_server.os.environ["LOCAL_PROXY_ALLOW"] = "127.0.0.1/32,::1/128,67.10.84.82/32"
    try:
        assert proxy_server.proxy_client_allowed(("::ffff:67.10.84.82", 50000))
        assert not proxy_server.proxy_client_allowed(("8.8.8.8", 1))
    finally:
        if old is None:
            proxy_server.os.environ.pop("LOCAL_PROXY_ALLOW", None)
        else:
            proxy_server.os.environ["LOCAL_PROXY_ALLOW"] = old


def test_udp_client_and_dest_family():
    assert proxy_server._udp_client_matches("127.0.0.1", "::ffff:127.0.0.1")
    assert proxy_server._udp_client_matches("::ffff:67.10.84.82", "67.10.84.82")
    assert not proxy_server._udp_client_matches("8.8.8.8", "67.10.84.82")


def test_enroll_mapped_source_uses_manual_cidr():
    with tempfile.TemporaryDirectory() as tmp:
        manager = ResourceShareManager(Path(tmp) / "share.json", node_pool=None, log_fn=lambda _m: None)
        invite = manager.create_invite("home", allowed_cidrs="67.10.84.82")
        result = manager.enroll(
            {"invite_code": invite["invite_code"], "peer_id": "peer-home"},
            ["::ffff:67.10.84.82"],
        )
        assert result["ok"] is True
        try:
            manager.enroll(
                {"invite_code": invite["invite_code"], "peer_id": "peer-other"},
                ["2001:db8::5"],
            )
        except PermissionError as exc:
            assert "67.10.84.82" not in str(exc) or "2001:db8::5" in str(exc)
        else:
            raise AssertionError("a different IPv6 must still be refused")


if __name__ == "__main__":
    test_manual_ipv4_accepts_mapped_form()
    test_forwarded_header_cannot_hide_the_tcp_peer()
    test_proxy_allow_manual_ip_after_other_family()
    test_udp_client_and_dest_family()
    test_enroll_mapped_source_uses_manual_cidr()
    print("ok")
