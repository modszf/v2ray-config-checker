# v2ray-config-checker
A Python tool to validate and check v2ray standalone configuration files

## Usage

```
python v2ray_checker.py config.json [more.json ...] [--run] [--binary v2ray|xray]
```

Performs static validation (JSON syntax, inbounds/outbounds, ports, tags, routing).
With `--run`, also tests the config using the v2ray/xray binary. Exit code is 1 if any config fails.

Tests: `pytest`
