# cf-tools

A growing collection of small, dependency-free tools for Cloudflare-related
networking tasks.

| Tool | Description |
|---|---|
| [`cfip.py`](#cfippy--cloudflare-edge-ip-optimizer) | Cloudflare edge IP optimizer for CDN-relayed WebSocket nodes |

More tools will be added over time — the repo name is intentionally generic.

## cfip.py — Cloudflare edge IP optimizer

`cfip.py` finds the fastest Cloudflare anycast edge IPs for *your* line and
verifies the full WebSocket chain end to end, then renders the ranking as a
self-contained HTML dashboard. Useful when your ISP's route to Cloudflare is
congested or unstable and different edge IPs land you in different colos
(LAX / SJC / HKG / NRT / FRA …).

### Candidate sources (highest → lowest priority)

1. `--from-file` — your own list, one IP per line, `#` comments allowed
2. Community-curated IP lists fetched online (failing sources are skipped):
   - `https://addressesapi.090227.xyz/CloudFlareYes`
   - `https://ip.164746.xyz/ipTop10.html`
   - append your own with `--source URL`
3. `cfip_list.txt` — a bundled offline fallback used **only** when every online
   source fails. Same-`/24` entries are de-duplicated (neighboring IPs behave
   almost identically). Edit this file to keep your own proven IPs.
4. Random sampling across all Cloudflare ranges (or `--cidr`) — **opt-in only**
   via `--scan`, always the lowest-priority filler up to `--num`.

### What gets tested

1. **TCP latency screen** — loss rate + median RTT, no ICMP involved
2. **Real TLS handshake** against your domain, with SNI and certificate
   validation — drops IPs that answer TCP but die on TLS (a pure ping-based
   test cannot see this)
3. **Deep loss re-test + single-stream download benchmark** — HTTP/1.1, the
   same transport WebSocket uses. Ranking score is
   `effective speed = download × success rate × TLS quality`, where handshakes
   slower than 800 ms are penalized as hidden packet loss
4. **Live WebSocket upgrade probe** — confirms `101`, flags `52x` (edge can't
   reach your origin), and reads the `cf-ray` header to show which colo each IP
   steers you to
5. Results are printed to the console and written to a timestamped HTML
   dashboard (`cfip_report_<timestamp>.html`, auto-opened; `--no-open` to skip)

### Usage

```bash
python3 cfip.py your.domain.com                    # list-first quick run
python3 cfip.py your.domain.com --scan             # opt in to random sampling
python3 cfip.py your.domain.com --path /ws         # validate the real WS path (101)
python3 cfip.py your.domain.com --port 2053        # try other CF TLS ports
python3 cfip.py your.domain.com --cidr 104.16.0.0/13          # constrain sampling
python3 cfip.py your.domain.com --from-file myips.txt         # your list only
```

Requirements: Python 3.8+ and `curl` (stock on macOS/Linux). No third-party
packages.

### Notes

- Benchmark bytes go straight to `/dev/null`; the only file the tool ever
  writes is the HTML report.
- You can only optimize the client → edge leg. If the edge → origin leg is the
  problem, you will see `52x` in the WS column.
- Point your client (V2RayU, etc.) at the winning IP while keeping Host/SNI and
  the WS path unchanged.
- Use responsibly and in accordance with your local laws and Cloudflare's ToS.
