import v2ray_checker as c

GOOD = {
    "inbounds": [{"tag": "in", "port": 1080, "protocol": "socks"}],
    "outbounds": [
        {"tag": "proxy", "protocol": "vmess", "settings": {"vnext": [
            {"address": "example.com", "port": 443,
             "users": [{"id": "uuid"}]}]}},
        {"tag": "direct", "protocol": "freedom"},
    ],
    "routing": {"rules": [{"inboundTag": ["in"], "outboundTag": "proxy"}]},
}


def test_good():
    assert c.validate(GOOD)[0] == []


def test_bad_port_and_tag():
    cfg = {"inbounds": [{"port": 70000, "protocol": "socks"}],
           "outbounds": [{"protocol": "freedom"}],
           "routing": {"rules": [{"outboundTag": "nope"}]}}
    errs = c.validate(cfg)[0]
    assert any("port" in e for e in errs)
    assert any("nope" in e for e in errs)


def test_no_outbounds():
    assert c.validate({"inbounds": []})[0]


def test_invalid_json(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("{")
    assert c.check_file(str(p))[0]
