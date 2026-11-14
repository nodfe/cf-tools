#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 优选 IP 脚本（配合 V2RayU 等 CF CDN 中转节点使用）

候选来源（按优先级, 随机扫描权重最低且默认关闭）:
  1. --from-file 指定的本地名单（每行一个 IP, 支持 # 注释）—— 给了就只用它
  2. 社区优选名单（在线拉取, --source 可追加自定义源）
  3. 在线名单拉不到时, 读脚本同目录的内置名单 cfip_list.txt（可自行编辑维护）
  4. --scan 开启时: 以上不够 --num 个, 再从 Cloudflare 全部网段（或 --cidr 指定段）随机补扫

筛选五步:
  1. TCP 连接测延迟初筛（不是 ICMP ping, 更贴近真实流量）, 按丢包+延迟排序
  2. 用真实伪装域名做完整 TLS 握手（带证书校验）:
     - WS 节点每次建连的真实开销是 TCP+TLS(+WS升级) ≈ 2~3 个 RTT, 只测 TCP 不够
     - 能剔除「TCP 通但 TLS 被重置 / 证书不对」的 IP
  3. 深度丢包复测（每个 IP 多次 TCP 连接, 丢包数字更可信）+ curl 走 speed.cloudflare.com
     实测单流下载速度（HTTP/1.1, 和 WS 一样单流）
  4. 真实 WebSocket 升级验证: 确认 101（或源站回落应答 200）、识别 52x（源站不可达）,
     并从 cf-ray 读出该 IP 把你调度到了哪个 CF 机房
  5. 按「有效速度 = 下载 × 连接成功率 × TLS质量系数」排名, 同时生成 HTML 看板

用法示例:
  python3 cfip.py 你的伪装域名                  # 默认: 名单优先 + 随机补扫, 共测 100 个
  python3 cfip.py 你的伪装域名 --path /yourws   # 节点 WS 路径不是 / 时指定, 101 校验才准确
  python3 cfip.py 你的伪装域名 --cidr 104.16.0.0/13    # 补扫时只在指定段里抽
  python3 cfip.py 你的伪装域名 --scan          # 名单测完后随机补扫到 --num 个
  python3 cfip.py 你的伪装域名 --no-list        # 跳过名单, 纯随机扫描（隐含 --scan）
  python3 cfip.py 你的伪装域名 --from-file myips.txt   # 只用自己的名单
  python3 cfip.py 你的伪装域名 --port 2053      # 443 被干扰时试试 CF 其他 TLS 端口
"""

import argparse
import base64
import html
import ipaddress
import os
import random
import re
import socket
import ssl
import statistics
import subprocess
import sys
import time
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor

CF_V4_URL = "https://www.cloudflare.com/ips-v4"

# 在线获取失败时用的内置列表（2026 年官方公布段）
FALLBACK_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

# 社区优选名单源（国内 VPS 定时实测维护; 拉取失败自动跳过, 落到内置名单兜底）
LIST_SOURCES = [
    "https://addressesapi.090227.xyz/CloudFlareYes",
    "https://ip.164746.xyz/ipTop10.html",
]

# 内置离线名单（脚本同目录, 社区在线名单全部拉不到时兜底; 可自行编辑维护）
BUILTIN_LIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cfip_list.txt")

# CF 支持 TLS 的端口: 443, 2053, 2083, 2087, 2096, 8443
SPEED_URL = "https://speed.cloudflare.com/__down?bytes={size}"
SPEED_HOST = "speed.cloudflare.com"

# cf-ray 尾部机房代码 -> 中文名（常见的几个）
COLO_NAMES = {
    "hkg": "香港", "nrt": "东京", "kix": "大阪", "sin": "新加坡", "icn": "首尔",
    "lax": "洛杉矶", "sjc": "圣何塞", "sea": "西雅图", "yvr": "温哥华",
    "dfw": "达拉斯", "ord": "芝加哥", "iad": "华盛顿", "atl": "亚特兰大",
    "fra": "法兰克福", "lhr": "伦敦",
}

BAD_WS = {"520", "521", "522", "523", "526", "527"}  # CF 连不上源站


def load_ranges():
    """获取 CF v4 网段列表（显式绕过环境变量代理, 和 curl 的 --noproxy 对齐）"""
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(CF_V4_URL, headers={"User-Agent": "curl/8.0"})
        text = opener.open(req, timeout=10).read().decode()
        ranges = [l.strip() for l in text.splitlines() if "/" in l]
        if len(ranges) < 5:
            raise ValueError("返回内容异常")
        return [ipaddress.ip_network(r) for r in ranges]
    except Exception as e:
        print(f"[!] 在线获取 CF 网段失败（{e}），改用内置列表")
        return [ipaddress.ip_network(r) for r in FALLBACK_RANGES]


def sample_ips(nets, n):
    """按网段大小的权重随机抽 n 个 IP（n 超过可用地址数时自动收敛到上限）"""
    weights = [net.num_addresses for net in nets]
    capacity = sum(weights) - 2 * len(nets)  # 去掉每个网段的网络/广播地址
    n = max(1, min(n, capacity))
    ips, misses = set(), 0
    while len(ips) < n and misses < 20000:
        before = len(ips)
        net = random.choices(nets, weights=weights)[0]
        offset = random.randrange(1, net.num_addresses - 1)
        ips.add(str(ipaddress.ip_address(int(net.network_address) + offset)))
        misses = misses + 1 if len(ips) == before else 0
    return list(ips)


def fetch_community_ips(sources, timeout=10):
    """并发拉取社区优选名单, 提取合法 IPv4, 按 /24 去重保序（同段邻居表现几乎一致）"""
    def grab(url):
        tag = url.split("//", 1)[-1]
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
            text = opener.open(req, timeout=timeout).read().decode("utf-8", "replace")
            found = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", text)
            print(f"      · {tag}: {len(found)} 个")
            return found
        except Exception as e:
            print(f"      · {tag}: 拉取失败({type(e).__name__}), 跳过")
            return []

    raw = []
    with ThreadPoolExecutor(max_workers=max(1, len(sources))) as ex:
        for found in ex.map(grab, sources):
            raw.extend(found)

    out, seen_ip, seen24 = [], set(), set()
    for ip in raw:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            continue
        if ip in seen_ip:
            continue
        seen_ip.add(ip)
        prefix = ip.rsplit(".", 1)[0]
        if prefix in seen24:
            continue
        seen24.add(prefix)
        out.append(ip)
    return out


def read_ip_file(path):
    """读名单文件: 每行一个 IP, 支持 # 行内注释; IP 去重 + 同 /24 只留一个"""
    out, seen_ip, seen24 = [], set(), set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            text = line.split("#", 1)[0].strip()
            if not text:
                continue
            try:
                ip = str(ipaddress.ip_address(text))
            except ValueError:
                continue
            if ip in seen_ip:
                continue
            seen_ip.add(ip)
            prefix = ip.rsplit(".", 1)[0]
            if prefix in seen24:  # 同 /24 邻居表现几乎一致, 只留一个省测试名额
                continue
            seen24.add(prefix)
            out.append(ip)
    return out


def tcp_ping(ip, port, probes, timeout):
    """对 ip:port 做 probes 次 TCP 连接，返回 (各次耗时ms列表, 失败次数, 总次数)"""
    times, lost = [], 0
    for _ in range(probes):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                times.append((time.perf_counter() - t0) * 1000)
        except OSError:
            lost += 1
        time.sleep(0.1)
    return times, lost, probes


def tls_handshake(ip, port, host, probes=2, timeout=3.0):
    """用真实域名做完整 TLS 握手（校验证书），返回 (各次耗时ms列表, 失败次数)"""
    ctx = ssl.create_default_context()
    times, errs = [], 0
    for _ in range(probes):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    times.append((time.perf_counter() - t0) * 1000)
        except OSError:
            errs += 1
    return times, errs


def ws_probe(ip, port, host, path, timeout=8.0):
    """发一次真实 WebSocket 升级请求，返回 (HTTP状态码, cf-ray机房代码, 说明)"""
    try:
        ctx = ssl.create_default_context()
        try:
            ctx.set_alpn_protocols(["http/1.1"])  # 和 WS 的 HTTP/1.1 保持一致
        except Exception:
            pass
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                key = base64.b64encode(os.urandom(16)).decode()
                req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                       f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                       f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
                tls.sendall(req.encode())
                tls.settimeout(timeout)
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
        lines = head.splitlines()
        status = lines[0] if lines else ""
        parts = status.split()
        code = parts[1] if len(parts) > 1 else "?"
        colo = ""
        for line in lines[1:]:
            if line.lower().startswith("cf-ray:"):
                colo = line.split(":", 1)[1].strip().rsplit("-", 1)[-1].lower()
        return code, colo, status
    except Exception as e:
        return "?", "", type(e).__name__


def download_speed(ip, port, size_mb, max_time):
    """用 curl 把域名解析强制指向该 IP，实测下载速度，返回 MB/s（失败返回 0）"""
    url = SPEED_URL.format(size=size_mb * 1024 * 1024)
    cmd = [
        "curl", "-k", "-so", "/dev/null",   # 数据直丢 /dev/null, 不落盘
        "--noproxy", "*",  # 关键: 绝对不要走 V2RayU 的代理，否则测的是代理速度
        "--http1.1",       # 和 WS 一样是 HTTP/1.1 单流，更有代表性
        "--resolve", f"{SPEED_HOST}:{port}:{ip}",
        "--max-time", str(max_time),
        "-w", "%{speed_download} %{http_code}",
        url,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except Exception:
        return 0.0
    out = r.stdout.strip().split()
    # --max-time 超时时 curl 退出码是 28, 但 -w 的指标仍然会输出, 照常解析
    if len(out) == 2 and out[1] == "200":
        try:
            speed = float(out[0])
            if speed > 0:
                return speed / 1024 / 1024
        except ValueError:
            pass
    return 0.0


def write_report(path, args, stats, ok, rejected, score):
    """生成自包含的 HTML 看板（无外部依赖, 直接浏览器打开）"""
    def esc(s):
        return html.escape(str(s))

    css = """
body{font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;margin:0;background:#f5f7fa;color:#1f2937}
.wrap{max-width:980px;margin:0 auto;padding:28px 20px}
h1{font-size:20px;margin:0 0 6px}
.sub{color:#6b7280;font-size:13px;margin-bottom:18px}
.best{background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;border-radius:12px;padding:18px 22px;margin-bottom:18px}
.best .lab{font-size:12px;opacity:.8}
.best .ip{font-size:26px;font-weight:700;font-family:Menlo,Consolas,monospace;margin:2px 0}
.best .meta{font-size:13px;opacity:.88;margin-top:4px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:6px}
th{background:#f9fafb;text-align:left;font-size:12px;color:#6b7280;padding:10px 12px;white-space:nowrap}
td{padding:9px 12px;border-top:1px solid #f3f4f6;font-size:13px;white-space:nowrap}
.mono{font-family:Menlo,Consolas,monospace}
.bad{color:#dc2626;font-weight:600}
.bar{height:6px;background:#e5e7eb;border-radius:3px;margin-top:4px;width:110px;min-width:110px}
.bar i{display:block;height:6px;border-radius:3px;background:linear-gradient(90deg,#2563eb,#06b6d4)}
.b{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600;white-space:nowrap}
.b-ok{background:#dcfce7;color:#15803d}.b-mid{background:#fef3c7;color:#b45309}
.b-bad{background:#fee2e2;color:#b91c1c}.b-dim{background:#f3f4f6;color:#6b7280}
.b-src{background:#e0e7ff;color:#4338ca}.b-colo{background:#ccfbf1;color:#0f766e}
details{margin-top:14px}summary{cursor:pointer;color:#6b7280;font-size:13px}
.foot{color:#9ca3af;font-size:12px;margin-top:18px;line-height:1.8}
"""

    def ws_badge(code):
        if code == "101":
            return '<span class="b b-ok">101 全链路</span>'
        if code in ("200", "301", "302"):
            return '<span class="b b-mid">回落 200</span>'
        if code in BAD_WS:
            return f'<span class="b b-bad">{esc(code)} 源站不可达</span>'
        if code == "?":
            return '<span class="b b-dim">超时</span>'
        return f'<span class="b b-dim">{esc(code)}</span>'

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    max_speed = max((r["speed"] for r in ok), default=1.0) or 1.0

    rows = []
    for i, r in enumerate(ok, 1):
        colo = (r["colo"] or "?").upper()
        tls_cls = ' class="bad"' if r["tls"] > 800 else ""
        w = max(3, round(r["speed"] / max_speed * 100))
        rows.append(f'''<tr>
          <td>{i}</td><td class="mono">{r["ip"]}</td>
          <td><span class="b b-src">{esc(r["src"])}</span></td>
          <td><span class="b b-colo">{esc(colo)} {esc(COLO_NAMES.get(r["colo"], ""))}</span></td>
          <td>{r["speed"]:.2f}<div class="bar"><i style="width:{w}%"></i></div></td>
          <td>{score(r):.2f}</td><td>{r["deep_lost"]}/{r["deep_probes"]}</td>
          <td>{r["median"]:.0f} ms</td><td{tls_cls}>{r["tls"]:.0f} ms</td>
          <td>{ws_badge(r["ws"])}</td></tr>''')

    best = ok[0]
    bcolo = (best["colo"] or "?").upper()
    best_card = f'''
    <div class="best">
      <div class="lab">推荐使用</div>
      <div class="ip">{best["ip"]}</div>
      <div class="meta">落地 {esc(bcolo)} {esc(COLO_NAMES.get(best["colo"], ""))} · 有效速度 {score(best):.2f} MB/s · 深测丢包 {best["deep_lost"]}/{best["deep_probes"]} · 来源 {esc(best["src"])}</div>
      <div class="meta">V2RayU 填法: 地址 = {best["ip"]} · 端口 = {args.port} · Host/SNI = {esc(args.domain)} · WS 路径 = 节点原路径</div>
    </div>'''

    rej = []
    for r in rejected:
        reason = "TLS 握手失败/证书异常" if r.get("tls") is None else "下载测速失败"
        rej.append(f'''<tr><td class="mono">{r["ip"]}</td><td>{esc(r["src"])}</td>
          <td>{reason}</td><td>{r["median"]:.0f} ms</td></tr>''')

    doc = f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CF 优选报告 · {esc(args.domain)}</title>
<style>{css}</style></head>
<body><div class="wrap">
<h1>Cloudflare 优选 IP 看板</h1>
<div class="sub">{esc(args.domain)} · 端口 {args.port} · {now} · 候选 {stats["total"]}（名单 {stats["list_count"]} + 随机 {stats["scan_count"]}）· TCP 存活 {stats["alive"]} · 测速成功 {stats["speed_ok"]}</div>
{best_card}
<table>
<tr><th>#</th><th>IP</th><th>来源</th><th>落地机房</th><th>下载 MB/s</th><th>有效速度</th><th>深测丢包</th><th>TCP</th><th>TLS</th><th>WS 验证</th></tr>
{''.join(rows)}
</table>
<details><summary>淘汰明细（{len(rejected)} 个）</summary>
<table><tr><th>IP</th><th>来源</th><th>原因</th><th>TCP 延迟</th></tr>{''.join(rej)}</table>
</details>
<div class="foot">
  WS=101 全链路验证通过 · WS=200 链路通(源站回落应答) · WS=52x CF 连不上你的源站 · 超时多为当时网络太差<br>
  有效速度 = 下载 × 连接成功率 × TLS质量(握手&gt;800ms打折) · 机房离你源站 VPS 越近, 代理内转发延迟越低<br>
  家里线路早晚质量不同, 建议早晚各跑一次: python3 cfip.py {esc(args.domain)}
</div>
</div></body></html>'''

    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


def main():
    ap = argparse.ArgumentParser(description="Cloudflare 优选 IP（社区名单优先 + WebSocket 全链路验证）")
    ap.add_argument("domain", help="伪装域名/SNI, 必填（即 V2RayU 里的 Host/SNI）")
    ap.add_argument("--path",  type=str, default="/", help="节点 WS 路径, 101 校验用 (默认 /)")
    ap.add_argument("--num",    type=int, default=100, help="候选 IP 上限 (默认 100; 未开 --scan 时名单超出会截断)")
    ap.add_argument("--port",   type=int, default=443, help="测试端口, 可用 443/2053/2083/2087/2096/8443 (默认 443)")
    ap.add_argument("--probes", type=int, default=3,   help="初筛每个 IP 的 TCP 连接次数 (默认 3)")
    ap.add_argument("--deep",   type=int, default=10,  help="决赛圈深度丢包探测次数 (默认 10)")
    ap.add_argument("--top",    type=int, default=10,  help="对延迟最低的前 N 名做深测 (默认 10)")
    ap.add_argument("--size",   type=int, default=30,  help="单次测速下载量 MB (默认 30)")
    ap.add_argument("--time",   type=int, default=8,   help="单次测速最长时间 秒 (默认 8)")
    ap.add_argument("--threads", type=int, default=64, help="延迟测试并发数 (默认 64)")
    ap.add_argument("--cidr", type=str, default="",
                    help="随机补扫只在指定网段(逗号分隔)里抽, 如 104.16.0.0/13,104.24.0.0/14 (默认全部)")
    ap.add_argument("--from-file", type=str, default="",
                    help="只用自己的名单文件(每行一个 IP, # 为注释), 跳过社区名单和随机补扫")
    ap.add_argument("--source", action="append", default=[], metavar="URL",
                    help="追加自定义社区名单 URL, 可多次使用")
    ap.add_argument("--scan", action="store_true",
                    help="开启随机补扫（默认关闭; 名单 IP 始终优先, 随机只用来补足 --num）")
    ap.add_argument("--no-list", action="store_true", help="跳过社区/内置名单, 纯随机扫描（隐含 --scan）")
    ap.add_argument("--out", type=str, default="", help="HTML 看板输出路径 (默认 cfip_report_时间戳.html)")
    ap.add_argument("--no-open", action="store_true", help="生成看板后不自动打开浏览器")
    args = ap.parse_args()

    print("[1/5] 获取候选 IP ...")
    entries = []  # (ip, 来源)

    if args.from_file:
        try:
            ips = read_ip_file(args.from_file)
        except OSError as e:
            print(f"[x] 读不了名单文件: {e}")
            sys.exit(1)
        entries = [(ip, "文件名单") for ip in ips[:args.num]]
        print(f"      从 {args.from_file} 读到 {len(entries)} 个 IP")
    elif not args.no_list:
        print("      拉取社区优选名单 ...")
        listed = fetch_community_ips(LIST_SOURCES + args.source)
        if listed:
            entries = [(ip, "社区名单") for ip in listed[:args.num]]
        else:
            print(f"      [!] 社区名单拉取失败, 改用内置名单兜底: {os.path.basename(BUILTIN_LIST)}")
            try:
                entries = [(ip, "内置名单") for ip in read_ip_file(BUILTIN_LIST)[:args.num]]
                print(f"      内置名单提供 {len(entries)} 个 IP")
            except OSError:
                print(f"      [x] 内置名单也读不到（{BUILTIN_LIST}）")

    # 随机补扫: 权重最低, 仅 --scan（或 --no-list 视为纯随机）时启用, 默认关闭
    if (args.scan or args.no_list) and len(entries) < args.num:
        if args.cidr:
            try:
                nets = [ipaddress.ip_network(c.strip()) for c in args.cidr.split(",") if c.strip()]
            except ValueError as e:
                print(f"[x] --cidr 格式错误: {e}")
                sys.exit(1)
            print(f"      补扫网段: {', '.join(str(n) for n in nets)}")
        else:
            nets = load_ranges()
            print(f"      补扫范围: CF 全部 {len(nets)} 个网段")
        have = {ip for ip, _ in entries}
        extra = [ip for ip in sample_ips(nets, args.num - len(entries) + 5) if ip not in have]
        entries += [(ip, "随机扫描") for ip in extra[:args.num - len(entries)]]

    if not entries:
        print("[x] 没有任何候选 IP —— 社区/内置名单都没读到; 检查 cfip_list.txt 或加 --scan 开启随机扫描")
        sys.exit(1)

    list_count = sum(1 for _, s in entries if s != "随机扫描")
    print(f"      共 {len(entries)} 个候选（名单优先测 {list_count} 个 + 随机 {len(entries) - list_count} 个）")
    if entries and len(entries) < args.num and not args.scan and not args.no_list and not args.from_file:
        print(f"      [i] 未开 --scan, 只测名单里的 {len(entries)} 个; 想测更多就加 --scan")

    src_map = dict(entries)
    candidates = [ip for ip, _ in entries]

    print(f"[2/5] TCP 延迟测试: {len(candidates)} 个 IP, 端口 {args.port}, 每个 {args.probes} 次 ...")

    results = []

    def worker(ip):
        times, lost, probes = tcp_ping(ip, args.port, args.probes, timeout=1.5)
        return ip, times, lost, probes

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for ip, times, lost, probes in ex.map(worker, candidates):
            if times:  # 至少连上过一次才算活
                results.append({
                    "ip": ip,
                    "src": src_map[ip],
                    "median": statistics.median(times),  # 中位延迟最抗抖动
                    "best": min(times),
                    "lost": lost,
                    "probes": probes,
                })

    if not results:
        print("[x] 所有 IP 都连不上 —— 检查网络或换个时间再试")
        sys.exit(1)

    results.sort(key=lambda r: (r["lost"] / r["probes"], r["median"]))
    preview = results[:args.top]
    for r in preview:
        print(f"      {r['ip']:<16} 延迟 {r['median']:6.0f}ms   丢包 {r['lost']}/{r['probes']}   [{r['src']}]")

    print(f"[3/5] TLS 握手测试: 前 {len(preview)} 名, 域名 {args.domain}（校验证书）...")
    tls_pool = []

    def tls_worker(r):
        times, errs = tls_handshake(r["ip"], args.port, args.domain)
        r["tls"] = statistics.median(times) if times else None
        r["tls_lost"] = errs
        return r

    with ThreadPoolExecutor(max_workers=8) as ex:
        tls_pool = list(ex.map(tls_worker, preview))

    finalists = []
    for r in tls_pool:
        if r["tls"] is not None:
            finalists.append(r)
            print(f"      {r['ip']:<16} TLS {r['tls']:5.0f}ms")
        else:
            print(f"      {r['ip']:<16} TLS 失败 x{r['tls_lost']}   (TCP 通但 TLS 不通/证书异常, 剔除)")

    if not finalists:
        print("[x] 所有候选 IP 的 TLS 握手都失败 —— 域名可能被墙/SNI 被阻断, 换时段重试或 --port 2053")
        sys.exit(1)

    print(f"[4/5] 深度丢包复测 + 下载测速: {len(finalists)} 个 IP, 每个最多 {args.time}s"
          f"（测速顺序执行, 约 {len(finalists) * args.time}s）...")

    def deep_worker(r):
        _, lost, probes = tcp_ping(r["ip"], args.port, max(1, args.deep), timeout=1.5)
        r["deep_lost"], r["deep_probes"] = lost, probes
        return r

    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(deep_worker, finalists))

    tested = []
    for r in finalists:
        speed = download_speed(r["ip"], args.port, args.size, args.time)
        r["speed"] = speed
        tested.append(r)
        mark = "" if speed > 0 else "   (测速失败, 可能丢包严重)"
        print(f"      {r['ip']:<16} 下载 {speed:6.2f} MB/s   深测丢包 {r['deep_lost']}/{r['deep_probes']}{mark}")

    ok = [r for r in tested if r.get("speed", 0) > 0]
    if not ok:
        print("[x] 没有任何 IP 测速成功 —— 当前网络到 CF 整体质量太差, 可换时段重试或试试 --port 2053/8443")
        sys.exit(1)

    print(f"[5/5] WebSocket 握手验证 + 识别落地机房 ({args.domain}, 路径 {args.path}) ...")
    for r in tested:
        code, colo, note = ws_probe(r["ip"], args.port, args.domain, args.path)
        r["ws"], r["colo"] = code, colo
        r["ws_bad"] = code in BAD_WS
        extra = ""
        if code == "101":
            extra = "  ← 全链路 WS 验证通过"
        elif code in ("200", "301", "302"):
            extra = "  ← 链路通(源站回落应答, 非WS路径)"
        elif r["ws_bad"]:
            extra = "  ← CF 连不上源站, 剔除!"
        elif code == "?":
            extra = f"  ({note}, 多为当时网络太差, 不代表IP差)"
        print(f"      {r['ip']:<16} WS {code:<4} 机房 {colo.upper() if colo else '?':<5}{extra}")

    # 排序: 52x 沉底, 再按「有效速度」兼顾丢包、速度和 TLS 质量
    def score(r):
        # TLS 握手 >800ms 是路径隐藏丢包的信号, 按比例打折
        tls_factor = min(1.0, 800.0 / max(1.0, r["tls"]))
        return r["speed"] * (1 - r["deep_lost"] / max(1, r["deep_probes"])) * tls_factor

    ok.sort(key=lambda r: (r["ws_bad"], -score(r), r["tls"]))
    print("\n========== 优选结果（按有效速度 = 下载 × 成功率 × TLS质量 排序, 52x 已沉底） ==========")
    print(f"{'排名':<4}{'IP':<17}{'有效速度':<11}{'下载':<12}{'深测丢包':<9}{'TCP':<9}{'TLS':<9}{'机房':<6}{'WS':<5}{'来源'}")
    for i, r in enumerate(ok, 1):
        colo = r["colo"].upper() if r["colo"] else "?"
        print(f"{i:<4}{r['ip']:<17}{score(r):6.2f}MB/s {r['speed']:6.2f}MB/s "
              f"{r['deep_lost']:>2}/{r['deep_probes']:<4}{r['median']:4.0f}ms  "
              f"{r['tls']:5.0f}ms  {colo:<6}{r['ws']:<5}{r['src']}")

    print("""
说明:
  WS=101     最理想: TCP+TLS+CF 转发+源站 WS 路径全链路验证通过
  WS=200 等  链路本身通（源站回落网站应答）; 想验证 WS 路径请 --path 指定真实路径
  WS=4xx     路径不对或被 WAF 拦, 不影响 IP 本身质量
  WS=52x     CF 到你的源站不通, 这个 IP 再快也不能用
  WS=?       当时网络太差没等到应答, 不代表 IP 差, 可重跑
  机房列     该 IP 把你调度到的 CF 机房; 离你源站 VPS 越近, 代理内转发延迟越低
  有效速度   下载 × 连接成功率 × TLS质量(握手>800ms打折); 想更准用 --deep 20
""")

    best = ok[0]
    colo = (best["colo"] or "?").upper()
    print(f"""
========== 推荐使用: {best['ip']}（有效速度 {score(best):.2f} MB/s, 深测丢包 {best['deep_lost']}/{best['deep_probes']}, 落地机房 {colo} {COLO_NAMES.get(best['colo'], '')}） ==========
在 V2RayU 中这样改:
  打开 V2RayU -> 服务器设置 -> 编辑你的节点:
  1.「地址 (Address)」改成: {best['ip']}
  2.「端口」保持你节点原本的端口
  3.「伪装域名 (Host)」和「SNI」保持 {args.domain} 不变
  4. WS「路径」保持你节点原本的路径
  5. 保存并重新连接, 试试看是否稳定

建议: 把前几名 IP 各存一个节点, 不稳时手动切换。
       家里线路早晚质量不同, 建议早晚各跑一次本脚本重新优选。
""")

    # HTML 看板
    stats = {
        "total": len(candidates),
        "alive": len(results),
        "speed_ok": len(ok),
        "list_count": list_count,
        "scan_count": len(entries) - list_count,
    }
    rejected = [r for r in tls_pool if r["tls"] is None]
    rejected += [r for r in tested if r.get("speed", 0) <= 0]
    report = args.out or f"cfip_report_{time.strftime('%Y%m%d_%H%M%S')}.html"
    write_report(report, args, stats, ok, rejected, score)
    print(f"[i] HTML 看板已生成: {os.path.abspath(report)}")
    if not args.no_open:
        webbrowser.open("file://" + os.path.abspath(report))


if __name__ == "__main__":
    main()
