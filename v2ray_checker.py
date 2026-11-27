#!/usr/bin/env python3
"""Validate v2ray standalone JSON config files.

Usage:
    python v2ray_checker.py config.json [more.json ...] [--run] [--binary v2ray]

Static checks are always performed. With --run, the config is also tested
by the v2ray/xray binary (`<binary> test -c <file>`, falling back to `-test`).
"""
import argparse
import base64
import binascii
import json
import shutil
import socket
import subprocess
import sys
from urllib.parse import parse_qs, unquote, urlsplit

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


SS_METHODS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-poly1305",
    "chacha20-ietf-poly1305", "xchacha20-poly1305", "xchacha20-ietf-poly1305",
    "none", "plain", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "rc4-md5", "chacha20",
    "chacha20-ietf", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
URL_SCHEMES = ("ss", "vmess", "vless", "trojan")


def _b64decode(data):
    data = unquote(data).strip()
    data += "=" * (-len(data) % 4)
    try:
        return base64.b64decode(data, altchars=b"-_", validate=False).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise ValueError("invalid base64 payload")


def parse_url(url):
    """Parse a share URL (ss/vmess/vless/trojan) into a dict:
    {scheme, name, host, port, params, method, password, id}."""
    url = url.strip()
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    if scheme not in URL_SCHEMES:
        raise ValueError(f"unsupported or missing scheme (expected one of {', '.join(URL_SCHEMES)})")
    rest = url.split("://", 1)[1]
    if scheme == "vmess":
        body = rest.split("#", 1)[0]
        try:
            j = json.loads(_b64decode(body))
        except json.JSONDecodeError:
            raise ValueError("vmess payload is not valid JSON")
        if not isinstance(j, dict):
            raise ValueError("vmess payload must be a JSON object")
        try:
            port = int(j.get("port"))
        except (TypeError, ValueError):
            raise ValueError(f"invalid port {j.get('port')!r}")
        return {"scheme": scheme, "name": j.get("ps", ""), "host": j.get("add", ""),
                "port": port, "id": j.get("id", ""),
                "params": {"type": j.get("net", "tcp"), "security": j.get("tls", "")}}
    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
    out = {"scheme": scheme, "name": unquote(frag), "method": "", "password": "", "id": ""}
    if scheme == "ss" and "@" not in rest.split("?", 1)[0]:
        # legacy form: base64(method:password@host:port)
        b, _, q = rest.partition("?")
        rest = _b64decode(b.rstrip("/")) + ("?" + q if q else "")
    u = urlsplit("//" + rest)
    try:
        port = u.port
    except ValueError:
        raise ValueError("invalid port")
    if port is None:
        raise ValueError("missing port")
    out["host"] = u.hostname or ""
    out["port"] = port
    out["params"] = {k: v[0] for k, v in parse_qs(u.query).items()}
    userinfo = unquote(u.netloc.rpartition("@")[0]) if "@" in u.netloc else ""
    if scheme == "ss":
        if ":" not in userinfo:
            userinfo = _b64decode(userinfo)
        if ":" not in userinfo:
            raise ValueError("userinfo must be method:password")
        out["method"], out["password"] = userinfo.split(":", 1)
    elif scheme == "trojan":
        out["password"] = userinfo
    else:
        out["id"] = userinfo
    return out


def validate_url(url):
    """Return (errors, warnings, info) for a share URL."""
    errors, warnings = [], []
    try:
        info = parse_url(url)
    except ValueError as e:
        return [str(e)], warnings, None
    if not info["host"]:
        errors.append("missing host")
    if not _port_ok(info["port"]):
        errors.append(f"invalid port {info['port']!r}")
    sc = info["scheme"]
    if sc == "ss":
        if not info["method"]:
            errors.append("missing cipher method")
        elif info["method"].lower() not in SS_METHODS:
            errors.append(f"unknown shadowsocks method '{info['method']}'")
        if not info["password"]:
            errors.append("missing password")
    elif sc == "trojan" and not info["password"]:
        errors.append("missing password")
    elif sc in ("vmess", "vless") and not info["id"]:
        errors.append("missing user id")
    net = info["params"].get("type", "tcp")
    if net not in NETWORKS:
        errors.append(f"unknown network type '{net}'")
    sec = info["params"].get("security", "")
    if sec not in SECURITY:
        errors.append(f"unknown security '{sec}'")
    if not info["name"]:
        warnings.append("no #name remark")
    return errors, warnings, info


def tcp_connect(host, port, timeout=5.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "TCP connect OK"
    except OSError as e:
        return False, f"TCP connect failed: {e}"


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
    ap.add_argument("files", nargs="+",
                    help="config files or ss:// vmess:// vless:// trojan:// URLs")
    ap.add_argument("--connect", action="store_true",
                    help="for URLs, also test TCP reachability of the server")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--run", action="store_true",
                    help="also test with the v2ray/xray binary")
    ap.add_argument("--binary", default="v2ray")
    a = ap.parse_args(argv)
    bad = 0
    for path in a.files:
        if "://" in path:
            errors, warnings, info = validate_url(path)
            if info and a.connect and not errors:
                ok, msg = tcp_connect(info["host"], info["port"], a.timeout)
                if not ok:
                    errors.append(msg)
            label = f"{info['scheme']}://{info['host']}:{info['port']} ({info['name']})" if info else path
            print(f"{label}: {'FAIL' if errors else 'OK'}")
            for e in errors:
                print(f"  error: {e}")
            for w in warnings:
                print(f"  warning: {w}")
            bad += bool(errors)
            continue
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
