#!/usr/bin/env python3
"""Validate v2ray standalone JSON config files.

Usage:
    python v2ray_checker.py config.json [more.json ...] [--run] [--binary v2ray]

Static checks are always performed. With --run, the config is also tested
by the v2ray/xray binary (`<binary> test -c <file>`, falling back to `-test`).
"""
import argparse
import json
import shutil
import subprocess
import sys

INBOUND_PROTOCOLS = {
    "dokodemo-door", "http", "mtproto", "shadowsocks", "socks",
    "vmess", "vless", "trojan", "wireguard", "tunnel",
}
OUTBOUND_PROTOCOLS = {
    "blackhole", "dns", "freedom", "http", "mtproto", "shadowsocks",
    "socks", "vmess", "vless", "trojan", "loopback", "wireguard",
}
NETWORKS = {"tcp", "kcp", "mkcp", "ws", "websocket", "http", "h2", "quic",
            "grpc", "httpupgrade", "splithttp", "xhttp", "raw"}
SECURITY = {"", "none", "tls", "xtls", "reality"}
SERVER_PROTOCOLS = {"vmess", "vless"}
LIST_SERVER_PROTOCOLS = {"shadowsocks", "socks", "http", "trojan"}


def _port_ok(p):
    if isinstance(p, int) and not isinstance(p, bool):
        return 1 <= p <= 65535
    if isinstance(p, str):
        parts = p.split("-")
        if 1 <= len(parts) <= 2 and all(x.strip().isdigit() for x in parts):
            nums = [int(x) for x in parts]
            return all(1 <= n <= 65535 for n in nums) and nums == sorted(nums)
    return False


def _check_stream(ss, where, errors, warnings):
    if not isinstance(ss, dict):
        errors.append(f"{where}.streamSettings must be an object")
        return
    net = ss.get("network", "tcp")
    if net not in NETWORKS:
        errors.append(f"{where}: unknown network '{net}'")
    sec = ss.get("security", "")
    if sec not in SECURITY:
        errors.append(f"{where}: unknown security '{sec}'")


def _check_outbound_servers(ob, where, errors, warnings):
    proto = ob.get("protocol")
    settings = ob.get("settings")
    if proto in ("freedom", "blackhole", "dns", "loopback"):
        return
    if not isinstance(settings, dict):
        errors.append(f"{where}: protocol '{proto}' requires 'settings' object")
        return
    if proto in SERVER_PROTOCOLS and "vnext" in settings:
        servers = settings["vnext"]
        key = "vnext"
    elif proto in LIST_SERVER_PROTOCOLS and "servers" in settings:
        servers = settings["servers"]
        key = "servers"
    elif proto in SERVER_PROTOCOLS or proto in LIST_SERVER_PROTOCOLS:
        if proto == "vless" and "address" in settings:  # xray flat form
            if not _port_ok(settings.get("port")):
                errors.append(f"{where}: invalid port {settings.get('port')!r}")
            return
        errors.append(f"{where}: protocol '{proto}' needs servers/vnext")
        return
    else:
        return
    if not isinstance(servers, list) or not servers:
        errors.append(f"{where}.settings.{key} must be a non-empty list")
        return
    for i, s in enumerate(servers):
        w = f"{where}.settings.{key}[{i}]"
        if not isinstance(s, dict):
            errors.append(f"{w} must be an object")
            continue
        if not s.get("address") or not isinstance(s["address"], str):
            errors.append(f"{w}: missing 'address'")
        if not _port_ok(s.get("port")):
            errors.append(f"{w}: invalid port {s.get('port')!r}")
        if key == "vnext":
            users = s.get("users")
            if not isinstance(users, list) or not users:
                errors.append(f"{w}: 'users' must be a non-empty list")
            else:
                for j, u in enumerate(users):
                    if not isinstance(u, dict) or not u.get("id"):
                        errors.append(f"{w}.users[{j}]: missing 'id'")
        elif proto == "shadowsocks":
            if not s.get("method"):
                errors.append(f"{w}: missing 'method'")
            if not s.get("password"):
                errors.append(f"{w}: missing 'password'")
        elif proto == "trojan" and not s.get("password"):
            errors.append(f"{w}: missing 'password'")


def validate(cfg):
    """Return (errors, warnings) for a parsed config."""
    errors, warnings = [], []
    if not isinstance(cfg, dict):
        return ["top-level value must be a JSON object"], warnings

    inbounds = cfg.get("inbounds", [])
    outbounds = cfg.get("outbounds", [])
    if "inbound" in cfg or "outbound" in cfg:
        warnings.append("legacy 'inbound'/'outbound' keys are deprecated")
    if not isinstance(inbounds, list):
        errors.append("'inbounds' must be a list")
        inbounds = []
    if not isinstance(outbounds, list):
        errors.append("'outbounds' must be a list")
        outbounds = []
    if not inbounds and "inbound" not in cfg:
        warnings.append("no inbounds defined")
    if not outbounds and "outbound" not in cfg:
        errors.append("no outbounds defined")

    in_tags, out_tags, ports = set(), set(), {}
    for i, ib in enumerate(inbounds):
        w = f"inbounds[{i}]"
        if not isinstance(ib, dict):
            errors.append(f"{w} must be an object")
            continue
        if ib.get("protocol") not in INBOUND_PROTOCOLS:
            errors.append(f"{w}: unknown protocol {ib.get('protocol')!r}")
        if "port" not in ib or not _port_ok(ib["port"]):
            errors.append(f"{w}: invalid or missing port {ib.get('port')!r}")
        else:
            key = (ib.get("listen", "127.0.0.1"), str(ib["port"]))
            if key in ports:
                errors.append(f"{w}: port {ib['port']} already used by {ports[key]}")
            ports[key] = w
        tag = ib.get("tag")
        if tag:
            if tag in in_tags:
                errors.append(f"{w}: duplicate tag '{tag}'")
            in_tags.add(tag)
        if "streamSettings" in ib:
            _check_stream(ib["streamSettings"], w, errors, warnings)

    for i, ob in enumerate(outbounds):
        w = f"outbounds[{i}]"
        if not isinstance(ob, dict):
            errors.append(f"{w} must be an object")
            continue
        if ob.get("protocol") not in OUTBOUND_PROTOCOLS:
            errors.append(f"{w}: unknown protocol {ob.get('protocol')!r}")
        tag = ob.get("tag")
        if tag:
            if tag in out_tags:
                errors.append(f"{w}: duplicate tag '{tag}'")
            out_tags.add(tag)
        _check_outbound_servers(ob, w, errors, warnings)
        if "streamSettings" in ob:
            _check_stream(ob["streamSettings"], w, errors, warnings)

    routing = cfg.get("routing")
    if routing is not None:
        if not isinstance(routing, dict):
            errors.append("'routing' must be an object")
        else:
            rules = routing.get("rules", [])
            if not isinstance(rules, list):
                errors.append("routing.rules must be a list")
                rules = []
            for i, r in enumerate(rules):
                w = f"routing.rules[{i}]"
                if not isinstance(r, dict):
                    errors.append(f"{w} must be an object")
                    continue
                if "outboundTag" not in r and "balancerTag" not in r:
                    errors.append(f"{w}: needs outboundTag or balancerTag")
                ot = r.get("outboundTag")
                if ot and ot not in out_tags:
                    errors.append(f"{w}: outboundTag '{ot}' not defined")
                for t in r.get("inboundTag", []) or []:
                    if t not in in_tags:
                        errors.append(f"{w}: inboundTag '{t}' not defined")
    return errors, warnings


def run_binary(path, binary):
    exe = shutil.which(binary)
    if not exe:
        return False, f"binary '{binary}' not found in PATH"
    for args in ([exe, "test", "-c", path], [exe, "-test", "-config", path]):
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return False, "binary timed out"
        if p.returncode == 0:
            return True, "binary accepted config"
        last = (p.stdout + p.stderr).strip()
    return False, last


def check_file(path, run=False, binary="v2ray"):
    errors, warnings = [], []
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except OSError as e:
        return [f"cannot read file: {e}"], warnings
    except json.JSONDecodeError as e:
        return [f"invalid JSON: {e}"], warnings
    errors, warnings = validate(cfg)
    if run and not errors:
        ok, msg = run_binary(path, binary)
        if not ok:
            errors.append(msg)
    return errors, warnings


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="+")
    ap.add_argument("--run", action="store_true",
                    help="also test with the v2ray/xray binary")
    ap.add_argument("--binary", default="v2ray")
    a = ap.parse_args(argv)
    bad = 0
    for path in a.files:
        errors, warnings = check_file(path, a.run, a.binary)
        print(f"{path}: {'FAIL' if errors else 'OK'}")
        for e in errors:
            print(f"  error: {e}")
        for w in warnings:
            print(f"  warning: {w}")
        bad += bool(errors)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
