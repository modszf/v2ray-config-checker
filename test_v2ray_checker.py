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


SS = ("ss://YWVzLTI1Ni1nY206OTNwak9ZaFlmV1B2blVxc0tqZFZxdjJVU0RuaHdrWHBsQStWUDZhMExKWT0"
      "@103.114.203.175:59036?type=tcp#Myanmar-Free8")


def test_ss_url():
    errs, _, info = c.validate_url(SS)
    assert errs == []
    assert info["method"] == "aes-256-gcm"
    assert (info["host"], info["port"], info["name"]) == ("103.114.203.175", 59036, "Myanmar-Free8")


def test_bad_urls():
    assert c.validate_url("ss://abc@h:99999")[0]
    assert c.validate_url("http://x")[0]
    assert c.validate_url("ss://YmFkbWV0aG9kOnB3@h:1")[0]
