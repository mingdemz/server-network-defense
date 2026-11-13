#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
服务器防御系统 (server_defense)
================================
纯防御型本地安全工具：安全基线审计、访问日志分析、轻量反向代理（迷你 WAF）
与文件完整性监控（FIM）。仅使用 Python 标准库，兼容 Windows / Linux，
以及 Python 3.10+（含 3.14）。

本工具不会执行任何攻击、密码破解、凭证提取或自动改写防火墙规则。
生成的封禁脚本必须由管理员审查后手动执行。
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import locale
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# 控制台与路径
# ---------------------------------------------------------------------------

TZ_SHANGHAI = timezone(timedelta(hours=8))
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_POLICY_PATH = SCRIPT_DIR / "defense_policy.json"
DEFAULT_SAMPLE_LOG = SCRIPT_DIR / "sample_access.log"

# 内置演示日志（当 sample_access.log 缺失时使用，仅含少量特征样本）
EMBEDDED_SAMPLE_LOG = """\
127.0.0.1 - - [13/Nov/2026:09:00:01 +0800] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
198.51.100.55 - - [13/Nov/2026:09:10:01 +0800] "GET /login?user=admin HTTP/1.1" 403 512 "-" "demo-scanner/1.0"
192.0.2.66 - - [13/Nov/2026:09:20:01 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:02 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:03 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:04 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:05 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:06 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:07 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:08 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:09 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:10 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:11 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:12 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:13 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:14 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:15 +0800] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
192.0.2.66 - - [13/Nov/2026:09:20:16 +0800] "POST /api/login HTTP/1.1" 429 64 "-" "python-requests/2.31.0"
"""

DEFAULT_POLICY: dict[str, Any] = {
    "rate_limit": {"window_seconds": 10, "max_requests": 30, "ban_seconds": 60},
    "request_max_bytes": 1048576,
    "high_risk_ports": [21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017],
    "allowlist_ips": [],
    "sensitive_paths": [
        ".env", ".git", ".svn", ".htaccess", ".htpasswd",
        "wp-login.php", "wp-config.php", "xmlrpc.php", "phpmyadmin",
        "adminer.php", "web.config", "id_rsa",
        "server-status", "actuator",
    ],
    "connection_threshold": 80,
    "brute_force": {"window_seconds": 60, "max_4xx": 15, "status_codes": [401, 403, 404, 429]},
    "alert_log": "defense_alerts.log",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_CN = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "信息",
}

PORT_HINTS = {
    21: "FTP（明文传输，易被滥用）",
    23: "Telnet（明文传输，应关闭）",
    135: "Windows RPC",
    139: "NetBIOS",
    445: "SMB 文件共享（常被蠕虫利用）",
    1433: "Microsoft SQL Server",
    1521: "Oracle 数据库",
    3306: "MySQL / MariaDB",
    3389: "远程桌面 (RDP)",
    5432: "PostgreSQL",
    5900: "VNC 远程桌面",
    6379: "Redis（未授权访问风险高）",
    27017: "MongoDB",
}


def configure_stdio() -> None:
    """在 Windows 上尽量把标准输出切到 UTF-8，避免中文乱码。"""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


def now_local() -> datetime:
    return datetime.now(TZ_SHANGHAI)


def iso_now() -> str:
    return now_local().isoformat(timespec="seconds")


def load_policy(path: Path | None = None) -> dict[str, Any]:
    """读取策略文件，缺失字段用内置默认值补齐。"""
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    target = path or DEFAULT_POLICY_PATH
    if target.is_file():
        try:
            with target.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                _deep_update(policy, data)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[警告] 无法读取策略文件 {target}：{exc}，改用内置默认策略。", file=sys.stderr)
    return policy


def _deep_update(base: dict, overlay: dict) -> None:
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_update(base[key], value)
        else:
            base[key] = value


def run_cmd(args: list[str], timeout: int = 20) -> tuple[int, str, str]:
    """执行外部命令，用系统首选编码解码输出（中文 Windows 多为 GBK）。"""
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            shell=False,
        )
    except FileNotFoundError:
        return 127, "", f"未找到命令：{args[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"命令超时：{' '.join(args)}"
    except OSError as exc:
        return 1, "", str(exc)

    stdout = _decode_cmd_output(completed.stdout)
    stderr = _decode_cmd_output(completed.stderr)
    return completed.returncode, stdout, stderr


def _decode_cmd_output(data: bytes) -> str:
    """Windows 系统命令常为 GBK，Python 3.14 又可能按 UTF-8 解码，这里按顺序尝试。"""
    if not data:
        return ""
    candidates = ["utf-8", "gb18030", "gbk", "cp936"]
    preferred = locale.getpreferredencoding(False)
    if preferred and preferred.lower() not in {c.lower() for c in candidates}:
        candidates.append(preferred)
    for enc in candidates:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def which(name: str) -> bool:
    from shutil import which as _which
    return _which(name) is not None


# ---------------------------------------------------------------------------
# 攻击特征检测（日志分析与迷你 WAF 共用，只做匹配识别）
# 规则由关键词组合编译，避免在源码中堆叠完整攻击语句。
# ---------------------------------------------------------------------------

def _rx(*parts: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile("".join(parts), flags)


def _build_detection_rules() -> list[tuple[str, str, str, re.Pattern[str]]]:
    """返回 (类别, 中文名, 严重级别, 正则) 列表。"""
    union, select, frm, where = r"\bunion\b", r"\bselect\b", r"\bfrom\b", r"\bwhere\b"
    or_kw, and_kw = r"\bor\b", r"\band\b"
    sleep, bench, wait = r"\bsleep\s*\(", r"\bbenchmark\s*\(", r"\bwaitfor\s+delay\b"
    info_sch, outfile, loadf = r"\binformation_schema\b", r"\binto\s+outfile\b", r"\bload_file\s*\("
    script_tag = r"<\s*script\b"
    js_proto = r"javascript\s*:"
    iframe = r"<\s*iframe\b"
    on_evt = r"\bon(?:error|load|click|mouseover|focus)\s*="
    cookie = r"document\.cookie"
    # 路径穿越：点点加斜杠的多种编码形式
    trav = r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c|\.\.%5c)"
    shell_bins = r"\b(cat|wget|curl|nc|ncat|bash|sh|cmd(?:\.exe)?|powershell(?:\.exe)?|chmod|python(?:3)?|whoami|id)\b"
    return [
        ("sql_injection", "SQL 注入探测", "high",
         _rx(r"(", union, r".+", select, r"|", select, r".+", frm, r".+", where, r")")),
        ("sql_injection", "SQL 注入探测", "high",
         _rx(r"('\s*(", or_kw, r"|", and_kw, r")\s+'?1'?\s*=\s*'?1|'\s*", or_kw, r"\s+'?\d+'?\s*=\s*'?\d+)")),
        ("sql_injection", "SQL 注入探测", "high",
         _rx(r"(", sleep, r"|", bench, r"|", wait, r"|", info_sch, r"|", outfile, r"|", loadf, r")")),
        ("xss", "XSS 跨站脚本", "high",
         _rx(r"(", script_tag, r"|", js_proto, r"|", iframe, r"|", on_evt, r"|", cookie, r")")),
        ("path_traversal", "路径穿越", "high", _rx(trav)),
        ("command_injection", "命令注入探测", "critical",
         _rx(r"([;&|`]\s*", shell_bins, r"|\b(?:wget|curl)\s+https?://)")),
        ("command_injection", "命令注入探测", "critical",
         _rx(r"(;\s*", shell_bins, r"|\|\s*", shell_bins, r")")),
    ]


ATTACK_PATTERNS = _build_detection_rules()

# 典型扫描器名称（代理端只拦截这类明确扫描器，不拦截普通 curl / 脚本库）
SCANNER_UA_RE = _rx(
    r"\b(",
    r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|dirb|wpscan|",
    r"acunetix|nessus|openvas|burpsuite|zgrab|wfuzz|nuclei|httpx|feroxbuster",
    r")\b",
)

# 日志分析时提示的自动化客户端（不作为代理拦截依据）
AUTOMATION_UA_RE = _rx(r"\b(python-requests|libwww-perl|curl/|wget/|go-http-client)\b")

SENSITIVE_PATH_RE_DEFAULT = _rx(
    r"(",
    r"(/|\\)(\.env|\.git|\.svn|\.htaccess|\.htpasswd|wp-login\.php|",
    r"wp-config\.php|xmlrpc\.php|phpmyadmin|adminer\.php|web\.config|",
    r"id_rsa|server-status|actuator|\.aws[/\\]credentials)(/|\\|$|\?)",
    r"|/\.env(?:$|\?)",
    r"|/etc/(?:passwd|shadow)(?:$|\?)",
    r")",
)


def compile_sensitive_regex(paths: Iterable[str]) -> re.Pattern[str]:
    escaped = [re.escape(item.strip()) for item in paths if (item or "").strip()]
    if not escaped:
        return SENSITIVE_PATH_RE_DEFAULT
    return re.compile(r"(?i)(" + "|".join(escaped) + r")")


def url_decode_loop(text: str, times: int = 3) -> str:
    """多次 URL 解码，减少编码绕过造成的漏报。"""
    current = text or ""
    for _ in range(times):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def inspect_request(
    raw_path: str,
    body: str = "",
    user_agent: str = "",
    sensitive_re: re.Pattern[str] | None = None,
    *,
    inspect_ua_for_proxy: bool = False,
) -> list[dict[str, str]]:
    """
    检查请求路径 / 查询串 / 正文 / UA，返回命中的攻击类别列表。
    每项包含 category / label / severity / evidence。
    """
    haystack = " ".join(
        filter(
            None,
            [
                raw_path or "",
                url_decode_loop(raw_path or ""),
                body or "",
                url_decode_loop(body or ""),
            ],
        )
    )
    hits: list[dict[str, str]] = []
    seen: set[str] = set()

    for category, label, severity, pattern in ATTACK_PATTERNS:
        match = pattern.search(haystack)
        if not match or category in seen:
            continue
        seen.add(category)
        evidence = match.group(0)
        if len(evidence) > 80:
            evidence = evidence[:77] + "..."
        hits.append({
            "category": category,
            "label": label,
            "severity": severity,
            "evidence": evidence,
        })

    sens = sensitive_re or SENSITIVE_PATH_RE_DEFAULT
    match = sens.search(haystack)
    if match and "sensitive_file" not in seen:
        evidence = match.group(0)
        if len(evidence) > 80:
            evidence = evidence[:77] + "..."
        hits.append({
            "category": "sensitive_file",
            "label": "敏感文件 / 后台探测",
            "severity": "medium",
            "evidence": evidence,
        })

    if user_agent:
        if SCANNER_UA_RE.search(user_agent):
            hits.append({
                "category": "scanner_ua",
                "label": "可疑扫描器 User-Agent",
                "severity": "medium",
                "evidence": user_agent[:80],
            })
        elif (not inspect_ua_for_proxy) and AUTOMATION_UA_RE.search(user_agent):
            hits.append({
                "category": "automation_ua",
                "label": "自动化脚本 User-Agent",
                "severity": "low",
                "evidence": user_agent[:80],
            })

    return hits


# ---------------------------------------------------------------------------
# 审计 (audit)
# ---------------------------------------------------------------------------

def parse_listen_address(addr: str) -> tuple[str, int] | None:
    addr = addr.strip()
    if addr.startswith("[") and "]:" in addr:
        host, port_s = addr.rsplit("]:", 1)
        host = host.lstrip("[")
    elif "]:" in addr:
        host, port_s = addr.rsplit("]:", 1)
        host = host.lstrip("[")
    elif addr.count(":") > 1:
        host, port_s = addr.rsplit(":", 1)
        host = host.strip("[]")
    else:
        if ":" not in addr:
            return None
        host, port_s = addr.rsplit(":", 1)
        host = host.strip("[]")
    try:
        port = int(port_s)
    except ValueError:
        return None
    if port < 0 or port > 65535:
        return None
    return host, port


def _is_wildcard(host: str) -> bool:
    host = host.strip().strip("[]").lower()
    return host in {"0.0.0.0", "::", "*", "::0"}


def collect_listening_ports() -> tuple[list[dict[str, Any]], str]:
    """采集本机正在监听的 TCP/UDP 端口。返回 (列表, 数据来源说明)。"""
    entries: list[dict[str, Any]] = []
    source = ""

    if sys.platform == "win32":
        code, out, err = run_cmd(["netstat", "-ano"])
        if code != 0:
            return [], f"netstat 失败：{err or out or f'exit {code}'}"
        source = "netstat -ano"
        entries = _parse_netstat_windows(out)
    else:
        if which("ss"):
            code, out, err = run_cmd(["ss", "-tuln"])
            if code == 0:
                source = "ss -tuln"
                entries = _parse_ss(out)
        if not entries and which("netstat"):
            code, out, err = run_cmd(["netstat", "-tuln"])
            if code == 0:
                source = "netstat -tuln"
                entries = _parse_netstat_linux(out)
            elif not source:
                return [], f"无法采集监听端口：{err or out}"
        if not source and not entries:
            return [], "系统中没有 ss 或 netstat，无法采集监听端口。"
    return entries, source


def _parse_netstat_windows(text: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        upper = line.upper()
        if not (upper.startswith("TCP") or upper.startswith("UDP")):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        proto = parts[0].upper()
        local = parts[1]
        state = ""
        pid = ""
        if proto.startswith("TCP"):
            if len(parts) >= 4:
                state = parts[3].upper()
            if len(parts) >= 5:
                pid = parts[4]
            if state and state not in {"LISTENING", "LISTEN"}:
                continue
        else:
            if len(parts) >= 4 and parts[-1].isdigit():
                pid = parts[-1]
        parsed = parse_listen_address(local)
        if not parsed:
            continue
        host, port = parsed
        key = (proto, host, port)
        if key in seen:
            continue
        seen.add(key)
        results.append({
            "protocol": "TCP" if proto.startswith("TCP") else "UDP",
            "address": host,
            "port": port,
            "state": state or "LISTENING",
            "pid": pid,
            "wildcard": _is_wildcard(host),
        })
    return results


def _parse_ss(text: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for raw in text.splitlines()[1:]:
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        state = parts[1].upper() if len(parts) > 1 else ""
        local = parts[4] if len(parts) > 4 else ""
        if proto.startswith("tcp") and state not in {"LISTEN", "LISTENING"}:
            continue
        if not (proto.startswith("tcp") or proto.startswith("udp")):
            continue
        parsed = parse_listen_address(local)
        if not parsed:
            continue
        host, port = parsed
        key = (proto, host, port)
        if key in seen:
            continue
        seen.add(key)
        results.append({
            "protocol": "TCP" if proto.startswith("tcp") else "UDP",
            "address": host,
            "port": port,
            "state": state or "LISTEN",
            "pid": "",
            "wildcard": _is_wildcard(host),
        })
    return results


def _parse_netstat_linux(text: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].lower()
        if not (proto.startswith("tcp") or proto.startswith("udp")):
            continue
        local = parts[3]
        state = parts[5].upper() if len(parts) > 5 else ""
        if proto.startswith("tcp") and state and state not in {"LISTEN", "LISTENING"}:
            continue
        parsed = parse_listen_address(local)
        if not parsed:
            continue
        host, port = parsed
        key = (proto, host, port)
        if key in seen:
            continue
        seen.add(key)
        results.append({
            "protocol": "TCP" if proto.startswith("tcp") else "UDP",
            "address": host,
            "port": port,
            "state": state or "LISTEN",
            "pid": "",
            "wildcard": _is_wildcard(host),
        })
    return results


def collect_connection_counts() -> tuple[dict[str, int], str]:
    """统计 ESTABLISHED 连接的对端 IP 出现次数。"""
    counts: dict[str, int] = defaultdict(int)
    source = ""
    if sys.platform == "win32":
        code, out, err = run_cmd(["netstat", "-ano"])
        if code != 0:
            return {}, f"netstat 失败：{err or out}"
        source = "netstat -ano"
        for raw in out.splitlines():
            line = raw.strip()
            if not line.upper().startswith("TCP"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            if parts[3].upper() != "ESTABLISHED":
                continue
            parsed = parse_listen_address(parts[2])
            if not parsed:
                continue
            host, _port = parsed
            if host in {"0.0.0.0", "*", "::"}:
                continue
            counts[host] += 1
    else:
        if which("ss"):
            code, out, err = run_cmd(["ss", "-tn", "state", "established"])
            if code == 0:
                source = "ss -tn state established"
                for raw in out.splitlines()[1:]:
                    parts = raw.split()
                    if len(parts) < 4:
                        continue
                    peer = parts[3]
                    parsed = parse_listen_address(peer)
                    if not parsed:
                        continue
                    counts[parsed[0]] += 1
        if not source and which("netstat"):
            code, out, err = run_cmd(["netstat", "-tn"])
            if code == 0:
                source = "netstat -tn"
                for raw in out.splitlines():
                    parts = raw.split()
                    if len(parts) < 5:
                        continue
                    if not parts[0].lower().startswith("tcp"):
                        continue
                    if parts[5].upper() not in {"ESTABLISHED", "ESTAB"}:
                        continue
                    parsed = parse_listen_address(parts[4])
                    if parsed:
                        counts[parsed[0]] += 1
    return dict(counts), source


def collect_firewall_status() -> dict[str, Any]:
    """读取本机防火墙概况。权限不足或命令不可用时优雅降级。"""
    info: dict[str, Any] = {"available": False, "tool": "", "profiles": [], "notes": []}
    if sys.platform == "win32":
        code, out, err = run_cmd(["netsh", "advfirewall", "show", "allprofiles"])
        info["tool"] = "netsh advfirewall"
        if code != 0:
            info["notes"].append(f"无法读取防火墙状态（可能权限不足）：{err or out or f'exit {code}'}")
            return info
        info["available"] = True
        current: dict[str, str] | None = None
        for raw in out.splitlines():
            line = raw.strip()
            if not line:
                continue
            lowered = line.lower()
            if re.search(r"profile\s+settings|配置文件.*设置", line, re.IGNORECASE):
                if current:
                    info["profiles"].append(current)
                current = {"name": line.rstrip(":：").strip(), "state": "unknown"}
            elif current is not None and (lowered.startswith("state") or line.startswith("状态")):
                parts = line.split()
                current["state"] = parts[-1] if parts else "unknown"
            elif current is not None and ("firewall policy" in lowered or "防火墙策略" in line):
                parts = re.split(r"\s{2,}", line, maxsplit=1)
                current["policy"] = parts[-1].strip() if len(parts) > 1 else line
        if current:
            info["profiles"].append(current)
        off_profiles = [
            p for p in info["profiles"]
            if str(p.get("state", "")).upper() in {"OFF", "禁用", "關閉", "关闭"}
        ]
        if off_profiles:
            info["notes"].append(
                "以下配置文件的防火墙处于关闭状态："
                + "、".join(p.get("name", "?") for p in off_profiles)
            )
        elif info["profiles"] and all(
            str(p.get("state", "")).upper() in {"ON", "启用", "啟用"} for p in info["profiles"]
        ):
            info["notes"].append("已检测到所有防火墙配置文件均处于开启状态。")
        return info

    if which("ufw"):
        code, out, err = run_cmd(["ufw", "status"])
        info["tool"] = "ufw"
        if code == 0:
            info["available"] = True
            info["raw_preview"] = "\n".join(out.strip().splitlines()[:15])
            first = (out.strip().splitlines() or [""])[0]
            info["notes"].append(first or "已读取 ufw 状态。")
            if re.search(r"inactive|未启用|未啟用", out, re.IGNORECASE):
                info["notes"].append("UFW 当前未启用。")
            return info
        info["notes"].append(f"ufw 状态读取失败：{err or out or f'exit {code}'}")

    if which("iptables"):
        code, out, err = run_cmd(["iptables", "-L", "-n"])
        info["tool"] = "iptables"
        if code == 0:
            info["available"] = True
            info["raw_preview"] = "\n".join(out.strip().splitlines()[:20])
            info["notes"].append("已读取 iptables 规则列表（可能需要 root 才能看到完整内容）。")
            return info
        info["notes"].append(f"iptables 读取失败（常见原因是权限不足）：{err or out or f'exit {code}'}")

    if which("firewall-cmd"):
        code, out, err = run_cmd(["firewall-cmd", "--state"])
        info["tool"] = "firewalld"
        if code == 0:
            info["available"] = True
            info["notes"].append(f"firewalld 状态：{out.strip() or '未知'}")
            return info

    if not info["notes"]:
        info["notes"].append("未找到 ufw / iptables / firewalld，跳过防火墙检查。")
    return info


def cmd_audit(args: argparse.Namespace) -> int:
    policy = load_policy(Path(args.policy) if getattr(args, "policy", None) else None)
    high_risk = {int(p) for p in policy.get("high_risk_ports", DEFAULT_POLICY["high_risk_ports"])}
    threshold = int(policy.get("connection_threshold", 80))

    print("=" * 60)
    print("服务器安全基线审计")
    print(f"时间：{iso_now()}（Asia/Shanghai）")
    print(f"主机：{socket.gethostname()}")
    print(f"系统：{sys.platform} / Python {sys.version.split()[0]}")
    print("=" * 60)

    findings: list[dict[str, Any]] = []

    ports, port_source = collect_listening_ports()
    print(f"\n[1] 监听端口（来源：{port_source or '不可用'}）")
    if not ports:
        print("    未能采集到监听端口。")
        findings.append({
            "severity": "medium",
            "title": "无法采集监听端口",
            "detail": port_source or "未知原因",
        })
    else:
        print(f"    共发现 {len(ports)} 个监听地址。")
        print(f"    {'协议':<6}{'地址':<28}{'端口':<8}{'范围':<10}{'说明'}")
        high_hits = []
        for item in sorted(ports, key=lambda x: (x["protocol"], x["port"], x["address"])):
            scope = "全部网卡" if item["wildcard"] else "本机/指定"
            hint = ""
            if item["port"] in high_risk and item["wildcard"]:
                hint = PORT_HINTS.get(item["port"], "高风险端口对外暴露")
                high_hits.append(item)
            elif item["port"] in high_risk:
                hint = "高风险端口（仅本机监听）"
            print(f"    {item['protocol']:<6}{item['address']:<28}{item['port']:<8}{scope:<10}{hint}")
        if high_hits:
            print(f"\n    ! 发现 {len(high_hits)} 个对外暴露的高风险端口，建议仅绑定到内网或通过防火墙限制来源。")
            for item in high_hits:
                findings.append({
                    "severity": "high",
                    "title": f"高风险端口对外暴露：{item['protocol']}/{item['port']}",
                    "detail": (
                        f"监听地址 {item['address']}:{item['port']} "
                        f"（{PORT_HINTS.get(item['port'], '高风险服务')}）"
                    ),
                })
        else:
            print("    未发现对 0.0.0.0 / :: 暴露的高风险端口。")
            findings.append({
                "severity": "info",
                "title": "未发现对外暴露的高风险端口",
                "detail": f"已检查 {len(ports)} 个监听地址。",
            })

    fw = collect_firewall_status()
    print(f"\n[2] 防火墙状态（工具：{fw.get('tool') or '未检测到'}）")
    if fw.get("profiles"):
        for profile in fw["profiles"]:
            print(f"    - {profile.get('name', '配置文件')}  状态：{profile.get('state', '未知')}")
    for note in fw.get("notes") or ["无额外说明。"]:
        print(f"    {note}")
    if not fw.get("available"):
        findings.append({
            "severity": "medium",
            "title": "未能完整读取防火墙状态",
            "detail": "；".join(fw.get("notes") or ["命令不可用或权限不足"]),
        })
    else:
        disabled = False
        for note in fw.get("notes") or []:
            if any(word in note for word in ("关闭", "未启用", "未啟用", "OFF", "inactive")):
                disabled = True
        if disabled:
            findings.append({
                "severity": "high",
                "title": "防火墙未全面启用",
                "detail": "；".join(fw.get("notes") or []),
            })
        else:
            findings.append({
                "severity": "info",
                "title": "已读取防火墙状态",
                "detail": "；".join(fw.get("notes") or ["看起来已启用"]),
            })

    counts, conn_source = collect_connection_counts()
    print(f"\n[3] 已建立连接按对端 IP 统计（来源：{conn_source or '不可用'}，阈值 {threshold}）")
    hotspots = []
    if not counts:
        print("    当前没有已建立的外部连接，或采集失败。")
    else:
        ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
        show = ranked[:15]
        for ip, num in show:
            mark = "  << 超过阈值" if num >= threshold else ""
            print(f"    {ip:<42} {num:>5} 条{mark}")
            if num >= threshold:
                hotspots.append({"ip": ip, "connections": num})
                findings.append({
                    "severity": "high",
                    "title": f"对端 IP 连接数异常：{ip}",
                    "detail": f"当前已建立连接 {num} 条，超过阈值 {threshold}，可能为扫描或洪水连接。",
                })
        if len(ranked) > 15:
            print(f"    …… 另有 {len(ranked) - 15} 个对端 IP 未全部列出。")
        if not hotspots:
            print("    未发现超过阈值的对端 IP。")
            findings.append({
                "severity": "info",
                "title": "连接数未见异常",
                "detail": f"共统计 {len(counts)} 个对端 IP，阈值 {threshold}。",
            })

    summary = {key: 0 for key in SEVERITY_CN}
    for item in findings:
        summary[item["severity"]] = summary.get(item["severity"], 0) + 1
    print("\n[4] 发现汇总")
    for key in ("critical", "high", "medium", "low", "info"):
        print(f"    {SEVERITY_CN[key]}：{summary.get(key, 0)}")

    report = {
        "generated_at": iso_now(),
        "timezone": "Asia/Shanghai",
        "hostname": socket.gethostname(),
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "listening_ports": ports,
        "port_source": port_source,
        "firewall": {
            "available": fw.get("available"),
            "tool": fw.get("tool"),
            "profiles": fw.get("profiles"),
            "notes": fw.get("notes"),
        },
        "connection_counts": counts,
        "connection_source": conn_source,
        "connection_hotspots": hotspots,
        "findings": findings,
        "summary": summary,
    }

    if getattr(args, "report", None):
        report_path = Path(args.report)
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(
                json.dumps(report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            print(f"\n已导出报告：{report_path.resolve()}")
        except OSError as exc:
            print(f"\n[错误] 无法写入报告 {report_path}：{exc}", file=sys.stderr)
            return 1
    return 0


# ---------------------------------------------------------------------------
# 日志分析 (scan-log)
# ---------------------------------------------------------------------------

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def parse_log_time(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        try:
            return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None


def analyze_log(path: Path, policy: dict[str, Any]) -> dict[str, Any]:
    sensitive_re = compile_sensitive_regex(policy.get("sensitive_paths") or [])
    brute_cfg = policy.get("brute_force") or {}
    window = int(brute_cfg.get("window_seconds", 60))
    max_4xx = int(brute_cfg.get("max_4xx", 15))
    status_watch = {int(x) for x in brute_cfg.get("status_codes", [401, 403, 404, 429])}
    allowlist = {str(ip) for ip in policy.get("allowlist_ips") or []}

    events: list[dict[str, Any]] = []
    ip_stats: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"total": 0, "hits": 0, "status_4xx": 0, "categories": set(), "times": []}
    )
    unparsed = 0
    total = 0
    comments = 0

    text = path.read_text(encoding="utf-8", errors="replace")
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            comments += 1
            continue
        total += 1
        match = LOG_RE.match(line)
        if not match:
            unparsed += 1
            continue
        info = match.groupdict()
        ip = info["ip"]
        status = int(info["status"])
        path_q = info["path"]
        ua = info.get("ua") or ""
        ts = parse_log_time(info["time"])
        ip_stats[ip]["total"] += 1
        if 400 <= status <= 499:
            ip_stats[ip]["status_4xx"] += 1
            if status in status_watch and ts is not None:
                ip_stats[ip]["times"].append(ts)

        hits = inspect_request(path_q, user_agent=ua, sensitive_re=sensitive_re)
        if not hits:
            continue
        if ip in allowlist:
            continue
        ip_stats[ip]["hits"] += 1
        for hit in hits:
            ip_stats[ip]["categories"].add(hit["category"])
            events.append({
                "line": lineno,
                "ip": ip,
                "time": info["time"],
                "method": info["method"],
                "path": path_q,
                "status": status,
                "user_agent": ua,
                **hit,
            })

    brute_ips: list[dict[str, Any]] = []
    for ip, stat in ip_stats.items():
        if ip in allowlist:
            continue
        times = sorted(stat["times"])
        burst = 0
        left = 0
        for right, t in enumerate(times):
            while (t - times[left]).total_seconds() > window:
                left += 1
            burst = max(burst, right - left + 1)
        if burst >= max_4xx:
            brute_ips.append({
                "ip": ip,
                "burst": burst,
                "window_seconds": window,
                "total_4xx": stat["status_4xx"],
            })
            events.append({
                "line": 0,
                "ip": ip,
                "time": "",
                "method": "",
                "path": "",
                "status": 0,
                "user_agent": "",
                "category": "brute_force",
                "label": "高频失败请求 / 疑似爆破",
                "severity": "high",
                "evidence": f"{window} 秒内至少 {burst} 次 4xx（阈值 {max_4xx}）",
            })
            stat["categories"].add("brute_force")
            stat["hits"] += 1

    suspects: list[dict[str, Any]] = []
    for ip, stat in ip_stats.items():
        if stat["hits"] <= 0:
            continue
        cats = sorted(stat["categories"])
        related = [e for e in events if e["ip"] == ip]
        severity = "low"
        for ev in related:
            if SEVERITY_ORDER.get(ev["severity"], 9) < SEVERITY_ORDER.get(severity, 9):
                severity = ev["severity"]
        suspects.append({
            "ip": ip,
            "events": len(related),
            "total_requests": stat["total"],
            "status_4xx": stat["status_4xx"],
            "categories": cats,
            "severity": severity,
        })
    suspects.sort(key=lambda s: (SEVERITY_ORDER.get(s["severity"], 9), -s["events"], s["ip"]))

    cat_counts: dict[str, int] = defaultdict(int)
    sev_counts: dict[str, int] = defaultdict(int)
    for ev in events:
        cat_counts[ev["category"]] += 1
        sev_counts[ev["severity"]] += 1

    return {
        "file": str(path),
        "generated_at": iso_now(),
        "total_lines": total,
        "comment_lines": comments,
        "unparsed_lines": unparsed,
        "events": events,
        "suspects": suspects,
        "brute_ips": brute_ips,
        "category_counts": dict(cat_counts),
        "severity_counts": dict(sev_counts),
    }


def print_log_report(result: dict[str, Any]) -> None:
    print("=" * 60)
    print("访问 / 安全日志分析")
    print(f"文件：{result['file']}")
    print(f"时间：{result['generated_at']}（Asia/Shanghai）")
    print("=" * 60)
    print(
        f"有效日志 {result['total_lines']} 行，注释 {result['comment_lines']} 行，"
        f"未能解析 {result['unparsed_lines']} 行。"
    )
    print("\n[1] 按攻击类别统计")
    if not result["category_counts"]:
        print("    未发现匹配的攻击特征。")
    else:
        labels = {
            "sql_injection": "SQL 注入探测",
            "xss": "XSS 跨站脚本",
            "path_traversal": "路径穿越",
            "command_injection": "命令注入探测",
            "sensitive_file": "敏感文件 / 后台探测",
            "scanner_ua": "可疑扫描器 UA",
            "automation_ua": "自动化脚本 UA",
            "brute_force": "高频失败请求 / 疑似爆破",
        }
        for key, count in sorted(result["category_counts"].items(), key=lambda kv: -kv[1]):
            print(f"    {labels.get(key, key):<24} {count:>5} 次")

    print("\n[2] 按严重级别统计")
    for key in ("critical", "high", "medium", "low"):
        print(f"    {SEVERITY_CN[key]}：{result['severity_counts'].get(key, 0)}")

    print("\n[3] 可疑 IP 汇总")
    if not result["suspects"]:
        print("    没有需要关注的 IP。")
    else:
        print(f"    {'IP':<22}{'级别':<6}{'事件':<8}{'总请求':<8}{'4xx':<6}类别")
        for item in result["suspects"]:
            cats = ",".join(item["categories"])
            print(
                f"    {item['ip']:<22}{SEVERITY_CN.get(item['severity'], item['severity']):<6}"
                f"{item['events']:<8}{item['total_requests']:<8}{item['status_4xx']:<6}{cats}"
            )

    preview = [e for e in result["events"] if e.get("path") or e["category"] == "brute_force"][:12]
    if preview:
        print("\n[4] 部分事件证据（最多 12 条）")
        for ev in preview:
            where = ev["path"] or ev["evidence"]
            print(
                f"    [{SEVERITY_CN.get(ev['severity'], ev['severity'])}] "
                f"{ev['ip']}  {ev['label']}  {where}"
            )


def write_block_script(path: Path, ips: list[str]) -> None:
    """生成供管理员审查后手动执行的封禁脚本，绝不自动执行。"""
    unique = []
    for ip in ips:
        if ip not in unique:
            unique.append(ip)
    stamp = iso_now()
    use_ps1 = path.suffix.lower() == ".ps1" or (path.suffix.lower() != ".sh" and sys.platform == "win32")
    if use_ps1:
        quoted = ", ".join("'" + ip.replace("'", "''") + "'" for ip in unique)
        lines = [
            "# 服务器防御系统生成的防火墙封禁脚本（PowerShell）",
            f"# 生成时间：{stamp}（Asia/Shanghai）",
            "# 警告：请管理员审查 IP 列表后再手动执行，本工具不会自动改防火墙。",
            "# 用法：以管理员身份打开 PowerShell，执行：",
            "#   Set-ExecutionPolicy -Scope Process Bypass; .\\block_ips.ps1",
            "",
            "$ErrorActionPreference = 'Stop'",
            f"$ips = @({quoted})",
            "foreach ($ip in $ips) {",
            "    $name = \"server_defense_block_$ip\"",
            "    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {",
            "        Write-Host \"规则已存在，跳过 $ip\"",
            "        continue",
            "    }",
            "    New-NetFirewallRule -DisplayName $name -Direction Inbound "
            "-RemoteAddress $ip -Action Block -Profile Any | Out-Null",
            "    Write-Host \"已添加封禁规则：$ip\"",
            "}",
            "",
        ]
        text = "\n".join(lines)
    else:
        ip_list = " ".join(unique)
        lines = [
            "#!/bin/sh",
            "# 服务器防御系统生成的防火墙封禁脚本（Linux）",
            f"# 生成时间：{stamp}（Asia/Shanghai）",
            "# 警告：请管理员审查 IP 列表后再手动执行，本工具不会自动改防火墙。",
            "# 优先尝试 ufw，否则使用 iptables。",
            "set -eu",
            "",
            f'IPS="{ip_list}"',
            "for ip in $IPS; do",
            "  if command -v ufw >/dev/null 2>&1; then",
            "    ufw deny from \"$ip\" comment 'server_defense_block'",
            "  elif command -v iptables >/dev/null 2>&1; then",
            "    iptables -C INPUT -s \"$ip\" -j DROP 2>/dev/null "
            "|| iptables -A INPUT -s \"$ip\" -j DROP",
            "  else",
            "    echo \"未找到 ufw 或 iptables，无法封禁 $ip\" >&2",
            "  fi",
            "done",
            "",
        ]
        text = "\n".join(lines)
    path.write_text(text, encoding="utf-8")
    if path.suffix.lower() == ".sh":
        try:
            path.chmod(path.stat().st_mode | 0o755)
        except OSError:
            pass


def cmd_scan_log(args: argparse.Namespace) -> int:
    policy = load_policy(Path(args.policy) if getattr(args, "policy", None) else None)
    log_path = Path(args.file) if getattr(args, "file", None) else DEFAULT_SAMPLE_LOG
    if not log_path.is_file():
        print(f"[错误] 找不到日志文件：{log_path}", file=sys.stderr)
        return 1
    try:
        result = analyze_log(log_path, policy)
    except OSError as exc:
        print(f"[错误] 读取日志失败：{exc}", file=sys.stderr)
        return 1
    print_log_report(result)

    if getattr(args, "report", None):
        report_path = Path(args.report)
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            print(f"\n已导出分析报告：{report_path.resolve()}")
        except OSError as exc:
            print(f"[错误] 无法写入报告：{exc}", file=sys.stderr)
            return 1

    if getattr(args, "gen_block_script", None):
        script_path = Path(args.gen_block_script)
        block_ips = [
            s["ip"] for s in result["suspects"]
            if s["severity"] in {"critical", "high", "medium"}
        ]
        try:
            script_path.parent.mkdir(parents=True, exist_ok=True)
            write_block_script(script_path, block_ips)
            print(f"\n已生成封禁脚本（不会自动执行，请先审查）：{script_path.resolve()}")
            if block_ips:
                print("待审查 IP：" + "、".join(block_ips))
            else:
                print("当前没有达到封禁建议级别的 IP，脚本内列表为空。")
        except OSError as exc:
            print(f"[错误] 无法写入封禁脚本：{exc}", file=sys.stderr)
            return 1
    return 0


# ---------------------------------------------------------------------------
# 迷你 WAF 反向代理 (shield-proxy)
# ---------------------------------------------------------------------------

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'self'",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


class RateLimiter:
    """按 IP 的滑动窗口限流，并在超限后进入临时封禁。"""

    def __init__(self, window: int, max_requests: int, ban_seconds: int, allowlist: Iterable[str]):
        self.window = max(1, int(window))
        self.max_requests = max(1, int(max_requests))
        self.ban_seconds = max(1, int(ban_seconds))
        self.allowlist = set(allowlist)
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._banned_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def check(self, ip: str, now: float | None = None) -> tuple[str, int]:
        """返回 (action, retry_after_seconds)。action: allow / rate_limited / banned"""
        now = time.time() if now is None else now
        if ip in self.allowlist:
            return "allow", 0
        with self._lock:
            until = self._banned_until.get(ip, 0.0)
            if until > now:
                return "banned", max(1, int(until - now))
            bucket = self._hits[ip]
            cutoff = now - self.window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                self._banned_until[ip] = now + self.ban_seconds
                bucket.clear()
                return "rate_limited", self.ban_seconds
            bucket.append(now)
            return "allow", 0


def parse_listen(value: str) -> tuple[str, int]:
    value = (value or "").strip()
    if value.startswith("["):
        host, port_s = value.rsplit("]:", 1)
        host = host[1:]
        return host, int(port_s)
    if ":" not in value:
        raise ValueError("监听地址格式应为 host:port，例如 127.0.0.1:8080")
    host, port_s = value.rsplit(":", 1)
    return host, int(port_s)


def parse_target(value: str) -> tuple[str, str, int, str]:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("后端地址格式应为 http://host:port 或 https://host:port")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    base_path = parsed.path or ""
    if base_path.endswith("/"):
        base_path = base_path[:-1]
    return parsed.scheme, parsed.hostname, port, base_path


class AlertLogger:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def write(self, message: str) -> None:
        line = f"{iso_now()} {message}\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)


def make_proxy_handler(
    target_scheme: str,
    target_host: str,
    target_port: int,
    target_base: str,
    policy: dict[str, Any],
    limiter: RateLimiter,
    alerts: AlertLogger,
    sensitive_re: re.Pattern[str],
):
    max_bytes = int(policy.get("request_max_bytes", 1048576))

    class DefenseProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "ServerDefenseProxy/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write("%s - %s\n" % (iso_now(), fmt % args))

        def _client_ip(self) -> str:
            return self.client_address[0] if self.client_address else "unknown"

        def _read_body(self) -> bytes | None:
            length = self.headers.get("Content-Length")
            if not length:
                return b""
            try:
                n = int(length)
            except ValueError:
                return b""
            if n < 0:
                return b""
            if n > max_bytes:
                return None
            return self.rfile.read(n)

        def _send_simple(self, code: int, body: str, extra: dict[str, str] | None = None) -> None:
            data = body.encode("utf-8")
            self.send_response(code)
            for key, value in SECURITY_HEADERS.items():
                self.send_header(key, value)
            if extra:
                for key, value in extra.items():
                    self.send_header(key, value)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _handle(self) -> None:
            ip = self._client_ip()
            action, retry_after = limiter.check(ip)
            if action in {"rate_limited", "banned"}:
                reason = "触发频率限制并进入临时封禁" if action == "rate_limited" else "仍在临时封禁冷却期内"
                alerts.write(f"[RATE] ip={ip} action={action} path={self.path} detail={reason}")
                self._send_simple(
                    429,
                    "请求过于频繁，请稍后再试。\n",
                    {"Retry-After": str(retry_after)},
                )
                return

            body = self._read_body()
            if body is None:
                alerts.write(f"[SIZE] ip={ip} path={self.path} 请求体超过 {max_bytes} 字节")
                self._send_simple(413, "请求体过大，已被防护代理拒绝。\n")
                return

            ua = self.headers.get("User-Agent", "")
            try:
                body_text = body.decode("utf-8", errors="replace")
            except Exception:
                body_text = ""
            hits = inspect_request(
                self.path,
                body=body_text,
                user_agent=ua,
                sensitive_re=sensitive_re,
                inspect_ua_for_proxy=True,
            )
            blockable = [h for h in hits if h["category"] != "automation_ua"]
            if blockable:
                labels = "、".join(sorted({h["label"] for h in blockable}))
                evidence = "; ".join(h["evidence"] for h in blockable)
                alerts.write(
                    f"[BLOCK] ip={ip} path={self.path} ua={ua!r} "
                    f"reasons={labels} evidence={evidence}"
                )
                self._send_simple(403, "请求被防护策略拦截。\n")
                return

            self._forward(body)

        def _forward(self, body: bytes) -> None:
            path = self.path or "/"
            if target_base and not path.startswith(target_base):
                if path.startswith("/"):
                    path = target_base + path
                else:
                    path = target_base + "/" + path
            conn: http.client.HTTPConnection | None = None
            try:
                if target_scheme == "https":
                    context = ssl.create_default_context()
                    conn = http.client.HTTPSConnection(
                        target_host, target_port, timeout=15, context=context
                    )
                else:
                    conn = http.client.HTTPConnection(target_host, target_port, timeout=15)
                headers = {}
                for key, value in self.headers.items():
                    if key.lower() in HOP_BY_HOP or key.lower() == "host":
                        continue
                    headers[key] = value
                headers["Host"] = f"{target_host}:{target_port}"
                headers["Connection"] = "close"
                conn.request(self.command, path, body=body or None, headers=headers)
                resp = conn.getresponse()
                payload = resp.read()
            except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
                alerts.write(f"[UPSTREAM] 转发失败 path={self.path} error={exc}")
                self._send_simple(502, "后端服务暂时不可用。\n")
                return
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass

            self.send_response(resp.status, resp.reason)
            sent = set()
            for key, value in resp.getheaders():
                if key.lower() in HOP_BY_HOP:
                    continue
                self.send_header(key, value)
                sent.add(key.lower())
            for key, value in SECURITY_HEADERS.items():
                if key.lower() not in sent:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        def do_GET(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def do_PUT(self) -> None:
            self._handle()

        def do_DELETE(self) -> None:
            self._handle()

        def do_HEAD(self) -> None:
            self._handle()

        def do_OPTIONS(self) -> None:
            self._handle()

        def do_PATCH(self) -> None:
            self._handle()

    return DefenseProxyHandler


def cmd_shield_proxy(args: argparse.Namespace) -> int:
    policy = load_policy(Path(args.policy) if getattr(args, "policy", None) else None)
    try:
        listen_host, listen_port = parse_listen(args.listen)
        scheme, host, port, base = parse_target(args.target)
    except ValueError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 2

    rate = policy.get("rate_limit") or {}
    limiter = RateLimiter(
        window=int(rate.get("window_seconds", 10)),
        max_requests=int(rate.get("max_requests", 30)),
        ban_seconds=int(rate.get("ban_seconds", 60)),
        allowlist=policy.get("allowlist_ips") or [],
    )
    alert_path = (
        Path(args.alert_log)
        if getattr(args, "alert_log", None)
        else Path(policy.get("alert_log") or "defense_alerts.log")
    )
    alerts = AlertLogger(alert_path)
    sensitive_re = compile_sensitive_regex(policy.get("sensitive_paths") or [])
    handler = make_proxy_handler(scheme, host, port, base, policy, limiter, alerts, sensitive_re)

    try:
        server = ThreadingHTTPServer((listen_host, listen_port), handler)
    except OSError as exc:
        print(f"[错误] 无法在 {listen_host}:{listen_port} 上监听：{exc}", file=sys.stderr)
        return 1

    print("=" * 60)
    print("防护反向代理（迷你 WAF）已启动")
    print(f"监听：http://{listen_host}:{listen_port}")
    print(f"转发到：{scheme}://{host}:{port}{base or ''}")
    print(f"限流：{limiter.window} 秒内最多 {limiter.max_requests} 次，超限封禁 {limiter.ban_seconds} 秒")
    print(f"告警日志：{alert_path.resolve()}")
    print("按 Ctrl+C 结束。本代理不会修改系统防火墙。")
    print("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止防护代理……")
    finally:
        server.shutdown()
        server.server_close()
    return 0


# ---------------------------------------------------------------------------
# 文件完整性监控 (fim)
# ---------------------------------------------------------------------------

SKIP_DIR_NAMES = {".git", "__pycache__", ".svn", ".hg", "node_modules"}


def iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            yield Path(dirpath) / name


def file_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def build_baseline(root: Path) -> dict[str, Any]:
    root = root.resolve()
    records: dict[str, Any] = {}
    for path in iter_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            stat = path.stat()
            records[rel] = {
                "sha256": file_digest(path),
                "size": stat.st_size,
                "mtime": int(stat.st_mtime),
            }
        except OSError as exc:
            records[rel] = {"error": str(exc)}
    return {
        "created_at": iso_now(),
        "root": str(root),
        "algorithm": "sha256",
        "file_count": len(records),
        "files": records,
    }


def compare_baseline(root: Path, baseline: dict[str, Any]) -> dict[str, Any]:
    root = root.resolve()
    old_files: dict[str, Any] = baseline.get("files") or {}
    current = build_baseline(root)
    new_files = current["files"]
    added, deleted, modified, errors = [], [], [], []
    for rel, meta in new_files.items():
        if "error" in meta:
            errors.append({"path": rel, "error": meta["error"]})
            continue
        if rel not in old_files:
            added.append(rel)
            continue
        old = old_files[rel]
        if old.get("sha256") and meta.get("sha256") and old["sha256"] != meta["sha256"]:
            modified.append({
                "path": rel,
                "old_sha256": old.get("sha256"),
                "new_sha256": meta.get("sha256"),
                "old_size": old.get("size"),
                "new_size": meta.get("size"),
            })
    for rel in old_files:
        if rel not in new_files:
            deleted.append(rel)
    return {
        "checked_at": iso_now(),
        "root": str(root),
        "baseline_created_at": baseline.get("created_at"),
        "added": sorted(added),
        "deleted": sorted(deleted),
        "modified": modified,
        "errors": errors,
        "current_count": len(new_files),
        "baseline_count": len(old_files),
    }


def cmd_fim(args: argparse.Namespace) -> int:
    root = Path(args.path)
    db = Path(args.db)
    if not root.exists() or not root.is_dir():
        print(f"[错误] 监控目录不存在或不是文件夹：{root}", file=sys.stderr)
        return 1

    if args.init:
        baseline = build_baseline(root)
        try:
            db.parent.mkdir(parents=True, exist_ok=True)
            # 建议把 --db 放在监控目录之外，避免基线文件自身被计入下次检查。
            db.write_text(json.dumps(baseline, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as exc:
            print(f"[错误] 无法写入基线文件：{exc}", file=sys.stderr)
            return 1
        print("=" * 60)
        print("文件完整性基线已创建")
        print(f"目录：{root.resolve()}")
        print(f"基线：{db.resolve()}")
        print(f"文件数：{baseline['file_count']}")
        print(f"时间：{baseline['created_at']}（Asia/Shanghai）")
        print("=" * 60)
        return 0

    if args.check:
        if not db.is_file():
            print(f"[错误] 找不到基线文件：{db}，请先使用 --init 创建。", file=sys.stderr)
            return 1
        try:
            baseline = json.loads(db.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[错误] 无法读取基线文件：{exc}", file=sys.stderr)
            return 1
        result = compare_baseline(root, baseline)
        print("=" * 60)
        print("文件完整性检查")
        print(f"目录：{result['root']}")
        print(f"基线创建时间：{result.get('baseline_created_at') or '未知'}")
        print(f"检查时间：{result['checked_at']}（Asia/Shanghai）")
        print("=" * 60)
        print(f"基线文件数：{result['baseline_count']}，当前文件数：{result['current_count']}")
        print(f"新增：{len(result['added'])}，修改：{len(result['modified'])}，删除：{len(result['deleted'])}")
        if result["added"]:
            print("\n[新增]")
            for item in result["added"]:
                print(f"    + {item}")
        if result["modified"]:
            print("\n[修改]")
            for item in result["modified"]:
                print(f"    * {item['path']}")
                print(f"        旧 SHA-256: {item['old_sha256']}")
                print(f"        新 SHA-256: {item['new_sha256']}")
        if result["deleted"]:
            print("\n[删除]")
            for item in result["deleted"]:
                print(f"    - {item}")
        if result["errors"]:
            print("\n[读取失败]")
            for item in result["errors"]:
                print(f"    ! {item['path']}  {item['error']}")
        if not (result["added"] or result["modified"] or result["deleted"]):
            print("\n未发现新增、修改或删除，目录与基线一致。")
        if getattr(args, "report", None):
            report_path = Path(args.report)
            try:
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(
                    json.dumps(result, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                print(f"\n已导出检查结果：{report_path.resolve()}")
            except OSError as exc:
                print(f"[错误] 无法写入报告：{exc}", file=sys.stderr)
                return 1
        return 0

    print("[错误] 请指定 --init 或 --check。", file=sys.stderr)
    return 2


# ---------------------------------------------------------------------------
# 离线演示 (demo)
# ---------------------------------------------------------------------------

def cmd_demo(args: argparse.Namespace) -> int:
    policy = load_policy(Path(args.policy) if getattr(args, "policy", None) else None)
    print("=" * 60)
    print("服务器防御系统 —— 离线演示")
    print(f"时间：{iso_now()}（Asia/Shanghai）")
    print("演示只做只读检查和临时目录实验，不会修改防火墙或删除你的文件。")
    print("=" * 60)

    print("\n>>>>>>>> 一、访问日志分析")
    cleanup_log = None
    if DEFAULT_SAMPLE_LOG.is_file():
        log_path = DEFAULT_SAMPLE_LOG
    else:
        tmp = Path(tempfile.mkdtemp(prefix="server_defense_demo_")) / "sample_access.log"
        tmp.write_text(EMBEDDED_SAMPLE_LOG, encoding="utf-8")
        log_path = tmp
        cleanup_log = tmp.parent
        print("    未找到附带的 sample_access.log，改用内置示例日志。")
    result = analyze_log(log_path, policy)
    print_log_report(result)

    print("\n>>>>>>>> 二、文件完整性监控演示（临时目录）")
    tmpdir = Path(tempfile.mkdtemp(prefix="server_defense_fim_"))
    try:
        (tmpdir / "index.html").write_text("<h1>ok</h1>\n", encoding="utf-8")
        (tmpdir / "app.js").write_text("console.log('ok');\n", encoding="utf-8")
        baseline = build_baseline(tmpdir)
        (tmpdir / "index.html").write_text("<h1>changed</h1>\n", encoding="utf-8")
        (tmpdir / "new_file.txt").write_text("这是演示用的新增文件。\n", encoding="utf-8")
        (tmpdir / "app.js").unlink()
        cmp = compare_baseline(tmpdir, baseline)
        print(f"    临时目录：{tmpdir}")
        print(f"    新增 {len(cmp['added'])}：{', '.join(cmp['added']) or '无'}")
        print(f"    修改 {len(cmp['modified'])}：{', '.join(m['path'] for m in cmp['modified']) or '无'}")
        print(f"    删除 {len(cmp['deleted'])}：{', '.join(cmp['deleted']) or '无'}")
        fim_ok = (
            "new_file.txt" in cmp["added"]
            and "app.js" in cmp["deleted"]
            and any(m["path"] == "index.html" for m in cmp["modified"])
        )
        print("    检测结果：" + ("三项变更均已正确识别。" if fim_ok else "部分变更未能识别，请检查程序。"))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
        if cleanup_log:
            shutil.rmtree(cleanup_log, ignore_errors=True)

    print("\n>>>>>>>> 三、本机端口与连接审计（只读）")
    audit_ns = argparse.Namespace(policy=getattr(args, "policy", None), report=None)
    cmd_audit(audit_ns)

    print("\n" + "=" * 60)
    print("演示结束。常用命令：")
    print("    python server_defense.py audit")
    print("    python server_defense.py scan-log --file sample_access.log")
    print("    python server_defense.py fim --init --path <目录> --db fim_baseline.json")
    print("    python server_defense.py fim --check --path <目录> --db fim_baseline.json")
    print("    python server_defense.py shield-proxy --listen 127.0.0.1:8080 --target http://127.0.0.1:8000")
    print("这是防御型监控与防护工具，不能替代系统更新、正规防火墙或云 WAF。")
    print("=" * 60)
    return 0


# ---------------------------------------------------------------------------
# 命令行入口
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="server_defense.py",
        description="服务器防御系统：安全基线审计、日志分析、防护反向代理与文件完整性监控（纯防御，标准库实现）。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  python server_defense.py demo\n"
            "  python server_defense.py audit --report report.json\n"
            "  python server_defense.py scan-log --file sample_access.log --gen-block-script block_ips.ps1\n"
            "  python server_defense.py shield-proxy --listen 127.0.0.1:8080 --target http://127.0.0.1:8000\n"
            "  python server_defense.py fim --init --path D:\\\\www --db fim_baseline.json\n"
            "  python server_defense.py fim --check --path D:\\\\www --db fim_baseline.json\n"
        ),
    )
    parser.add_argument("--policy", default=None, help="策略文件路径（默认使用程序目录下的 defense_policy.json）")
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit", help="本机安全基线审计（监听端口 / 防火墙 / 连接数）")
    p_audit.add_argument("--report", default=None, help="将审计结果导出为 JSON，例如 report.json")
    p_audit.add_argument("--policy", default=None, help="策略文件路径")
    p_audit.set_defaults(func=cmd_audit)

    p_log = sub.add_parser("scan-log", help="分析访问 / 安全日志中的攻击特征")
    p_log.add_argument("--file", default=str(DEFAULT_SAMPLE_LOG), help="日志文件路径（默认 sample_access.log）")
    p_log.add_argument("--report", default=None, help="将分析结果导出为 JSON")
    p_log.add_argument(
        "--gen-block-script",
        default=None,
        help="生成供管理员审查后手动执行的封禁脚本（.ps1 或 .sh），不会自动执行",
    )
    p_log.add_argument("--policy", default=None, help="策略文件路径")
    p_log.set_defaults(func=cmd_scan_log)

    p_proxy = sub.add_parser("shield-proxy", help="启动本地防护反向代理（迷你 WAF）")
    p_proxy.add_argument("--listen", default="127.0.0.1:8080", help="监听地址，默认 127.0.0.1:8080")
    p_proxy.add_argument("--target", default="http://127.0.0.1:8000", help="后端地址，默认 http://127.0.0.1:8000")
    p_proxy.add_argument("--alert-log", default=None, help="告警日志路径，默认 defense_alerts.log")
    p_proxy.add_argument("--policy", default=None, help="策略文件路径")
    p_proxy.set_defaults(func=cmd_shield_proxy)

    p_fim = sub.add_parser("fim", help="文件完整性监控（创建基线或检查变更）")
    group = p_fim.add_mutually_exclusive_group(required=True)
    group.add_argument("--init", action="store_true", help="创建 SHA-256 基线")
    group.add_argument("--check", action="store_true", help="对照基线检查新增 / 修改 / 删除")
    p_fim.add_argument("--path", required=True, help="要监控的目录")
    p_fim.add_argument("--db", required=True, help="基线数据库文件（JSON）")
    p_fim.add_argument("--report", default=None, help="检查结果导出为 JSON")
    p_fim.set_defaults(func=cmd_fim)

    p_demo = sub.add_parser("demo", help="离线演示：日志分析 + 临时 FIM + 本机审计")
    p_demo.add_argument("--policy", default=None, help="策略文件路径")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2
    try:
        return int(func(args) or 0)
    except KeyboardInterrupt:
        print("\n已取消。")
        return 130


if __name__ == "__main__":
    sys.exit(main())
