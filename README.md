# v2ray-config-checker
A Python tool to validate and check v2ray standalone configuration files

## Usage

```
python v2ray_checker.py config.json [more.json ...] [--run] [--binary v2ray|xray]
```

Performs static validation (JSON syntax, inbounds/outbounds, ports, tags, routing).
With `--run`, also tests the config using the v2ray/xray binary. Exit code is 1 if any config fails.

Tests: `pytest`

## Share URLs

`ss://`, `vmess://`, `vless://` and `trojan://` URLs can be passed instead of files; they are parsed and validated.
Add `--connect` to also test TCP reachability of the server:

```
python v2ray_checker.py 'ss://...@1.2.3.4:59036?type=tcp#name' --connect
```

When `--connect` succeeds, the server's IP location (e.g. `Singapore, Singapore (SG)`) is printed
using ip-api.com. Use `--no-geo` to skip the lookup.
