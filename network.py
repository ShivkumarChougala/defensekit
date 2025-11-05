# Defense/network_scanner.py
import socket
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Tuple, Optional

import pandas as pd
import streamlit as st

def network_page():
    """
    Simple, user-friendly Network Port Scanner (single-threaded behavior, no blacklist, no timeout control).
    - Presets: Common, Top-100, Vulnerable, Custom
    - Single top-level function to import and call
    """
    # ---------------- UI & presets ----------------
    st.header("🧭 Network Port Scanner — simple & friendly")
    st.write("Pick a preset or use Custom ports. Enter a host (domain or IPv4) and click **Scan**.")

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 123, 143, 161, 194, 443, 465, 587, 993, 995, 3306, 3389, 5900, 8080]
    TOP_100_PORTS = [
        1,3,7,9,13,17,19,20,21,22,23,25,26,37,53,79,80,81,82,83,88,109,110,111,113,119,123,135,139,
        143,161,179,199,389,443,445,465,514,515,523,526,530,531,532,543,544,548,554,587,631,636,989,
        990,992,993,994,995,1080,1194,1433,1434,1521,1723,1883,1900,2049,2082,2083,2095,2096,2121,2181,
        2222,2375,2483,3000,3128,3306,3389,3478,3632,4333,4444,4662,4993,5000,5060,5061,5101,5432,5666,
        5800,5900,6000,6379,6667,6697,6881,6969,7000,8000,8080,8443,8888,9000,9001,9090,9100,9999
    ]
    VULN_PORTS = [21, 22, 23, 25, 69, 80, 135, 139, 445, 3389, 5900, 3306, 1433, 1521]

    # ---------------- helpers ----------------
    def resolve_host(host: str) -> Tuple[str, Optional[str]]:
        try:
            ip = socket.gethostbyname(host)
            try:
                rev = socket.gethostbyaddr(ip)[0]
            except Exception:
                rev = None
            return ip, rev
        except Exception:
            return host, None

    def parse_custom_ports(text: str) -> List[int]:
        ports = set()
        for part in (p.strip() for p in text.split(",") if p.strip()):
            if "-" in part:
                try:
                    a, b = part.split("-", 1)
                    a_i, b_i = int(a), int(b)
                    if a_i > b_i:
                        a_i, b_i = b_i, a_i
                    # safety cap: avoid huge ranges
                    if b_i - a_i > 5000:
                        continue
                    ports.update(range(max(1, a_i), min(65535, b_i) + 1))
                except Exception:
                    continue
            else:
                try:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.add(p)
                except Exception:
                    continue
        return sorted(ports)

    def scan_single_port(host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            # try small banner read
            try:
                s.settimeout(0.5)
                data = s.recv(512)
                banner = data.decode(errors="ignore").strip()[:200] if data else ""
            except Exception:
                banner = ""
            finally:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                s.close()
            return port, True, banner or ""
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            return port, False, ""

    # ---------------- UI inputs ----------------
    col1, col2 = st.columns([2, 1])
    with col1:
        target = st.text_input("Target (hostname or IPv4)", placeholder="example.com or 1.2.3.4")
    with col2:
        preset = st.selectbox("Preset ports", ["Common (quick)", "Top-100", "Vulnerable (quick)", "Custom"])
        # fixed sensible defaults (no threads, no timeout control shown)
        timeout = 1.0  # single default timeout for sockets

    custom_input = ""
    if preset == "Custom":
        custom_input = st.text_input("Custom ports (e.g. 22,80,8000-8100)", placeholder="22,80,443")

    scan_btn = st.button("Scan", key="simple_net_scan")

    st.markdown("**Tips:** Use presets for quick scans. Custom ranges should be reasonably small.")

    # ---------------- Action: Scan ----------------
    if scan_btn:
        if not target or not target.strip():
            st.warning("Enter a target hostname or IP.")
        else:
            target = target.strip()
            resolved_ip, rev = resolve_host(target)
            st.write(f"Target: `{target}` → `{resolved_ip}`")
            if rev:
                st.write(f"Reverse DNS: `{rev}`")

            # choose ports
            if preset == "Common (quick)":
                ports = COMMON_PORTS
            elif preset == "Top-100":
                ports = TOP_100_PORTS
            elif preset == "Vulnerable (quick)":
                ports = VULN_PORTS
            else:  # Custom
                ports = parse_custom_ports(custom_input)
                if not ports:
                    st.warning("No valid custom ports parsed. Example: 22,80,443 or 1-1024")
                    st.stop()

            st.info(f"Scanning {len(ports)} ports on {resolved_ip} (this may take a few seconds).")
            progress = st.progress(0)
            status = st.empty()

            results = []
            total = len(ports)
            done = 0

            start = time.time()
            # single-threaded / sequential scanning to keep it simple for users
            for p in ports:
                port, is_open, banner = scan_single_port(resolved_ip, p, timeout)
                results.append({"port": port, "open": is_open, "banner": (banner or "")})
                done += 1
                progress.progress(int(done / total * 100))
                status.text(f"Scanned {done}/{total}")

            elapsed = time.time() - start
            open_count = sum(1 for r in results if r["open"])
            st.success(f"Scan finished in {elapsed:.1f}s — {open_count} open port(s) found")

            # show results
            df = pd.DataFrame(results).sort_values(by=["open", "port"], ascending=[False, True]).reset_index(drop=True)
            df["status"] = df["open"].apply(lambda x: "open" if x else "closed")
            df_display = df[["port", "status", "banner"]].rename(columns={"banner": "banner (truncated)"})
            st.dataframe(df_display, use_container_width=True)

            # CSV download
            csv_bytes = df.to_csv(index=False).encode("utf-8")
            st.download_button("Download results (CSV)", csv_bytes, file_name=f"scan_{resolved_ip}.csv", mime="text/csv")

            # friendly actions if open ports
            if open_count:
                st.markdown("### Actions")
                st.write("If the target is unwanted or malicious, you can block it on your firewall (example commands shown).")
                st.markdown("Suggested firewall commands (run on your host):")
                st.code(f"sudo ufw deny from {resolved_ip} to any\nsudo iptables -A INPUT -s {resolved_ip} -j DROP")
            else:
                st.info("No open ports found in the scanned list.")
