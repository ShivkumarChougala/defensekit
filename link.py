import os
import time
import base64
import requests
import streamlit as st
import pandas as pd
from dotenv import load_dotenv

def link_page():
    """
    Streamlit merged page: 
    - Tab A: URL Scanner (VirusTotal)
    - Tab B: Domain/IP Reputation Defender (AbuseIPDB)
 
    """
    # ---------------- Setup ----------------
    load_dotenv()
    VT_API_KEY = os.getenv("VT_API_KEY")
    ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API")
    VT_BASE = "https://www.virustotal.com/api/v3"
    ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

    st.set_page_config(page_title="Threat Intelligence", page_icon="🛡️", layout="centered")
    st.title("🛡️ Threat Intelligence Center")
    st.caption("URL scanning (VirusTotal) and IP/Domain reputation (AbuseIPDB) in one place.")

    # ------------ helper functions ------------
    def encode_url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def vt_submit_url(url: str):
        headers = {"x-apikey": VT_API_KEY}
        r = requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url}, timeout=15)
        return r

    def vt_get_analysis(analysis_id: str):
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=15)
        return r

    def vt_get_url_report_by_url(url: str):
        headers = {"x-apikey": VT_API_KEY}
        url_id = encode_url_id(url)
        r = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=15)
        return r

    def abuseipdb_check(ip_or_domain: str, max_age_days: int = 90):
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_KEY}
        params = {"ipAddress": ip_or_domain, "maxAgeInDays": max_age_days}
        r = requests.get(ABUSE_CHECK_URL, headers=headers, params=params, timeout=15)
        return r

    # ------------ UI Tabs ------------
    tab1, tab2 = st.tabs(["🔗 URL Scanner (VirusTotal)", "🌐 Domain/IP Reputation (AbuseIPDB)"])

    # ---------------- Tab 1: VirusTotal ----------------
    with tab1:
        st.markdown("**Submit a URL to VirusTotal and view the results.**")
        url_input = st.text_input("Enter URL to scan", placeholder="https://example.com")

        if st.button("Scan", key="vt_scan"):
            if not url_input or not url_input.strip():
                st.warning("Please enter a URL to scan.")
            elif not VT_API_KEY:
                st.error("VirusTotal API key missing. Set VT_API_KEY in your .env.")
            else:
                url_input = url_input.strip()
                try:
                    with st.spinner("Submitting URL to VirusTotal..."):
                        submit_res = vt_submit_url(url_input)
                    if submit_res.status_code not in (200, 201):
                        st.error(f"Submission failed ({submit_res.status_code}): {submit_res.text}")
                    else:
                        analysis_id = submit_res.json().get("data", {}).get("id")
                        if not analysis_id:
                            st.error("Could not obtain analysis ID from VT.")
                        else:
                            st.info("Waiting for VirusTotal to finish analysis (polling)...")
                            analysis = None
                            status = None
                            # Poll loop with exponential backoff-ish behavior but capped attempts
                            sleep = 1.5
                            for attempt in range(18):  # ~ up to ~30s (adjust as needed)
                                a_res = vt_get_analysis(analysis_id)
                                if a_res.status_code == 200:
                                    analysis = a_res.json()
                                    status = analysis.get("data", {}).get("attributes", {}).get("status")
                                    if status == "completed":
                                        break
                                time.sleep(sleep)
                                # gradually increase wait to avoid tight loop
                                sleep = min(sleep * 1.2, 5)

                            if status != "completed":
                                st.warning("Analysis still processing. Please check the full report link shortly.")
                                vt_gui_link = f"https://www.virustotal.com/gui/url/{encode_url_id(url_input)}"
                                st.markdown(f"[Open VirusTotal report]({vt_gui_link})")
                            else:
                                # Fetch final URL report for per-engine results
                                report_res = vt_get_url_report_by_url(url_input)
                                if report_res.status_code != 200:
                                    st.error(f"Failed to fetch final VT report ({report_res.status_code}).")
                                else:
                                    report_json = report_res.json()
                                    attrs = report_json.get("data", {}).get("attributes", {})
                                    stats = attrs.get("last_analysis_stats", {})
                                    results = attrs.get("last_analysis_results", {})

                                    malicious = stats.get("malicious", 0)
                                    suspicious = stats.get("suspicious", 0)
                                    harmless = stats.get("harmless", 0)
                                    undetected = stats.get("undetected", 0)

                                    st.subheader("📊 Scan Summary")
                                    c1, c2, c3, c4 = st.columns(4)
                                    c1.metric("Malicious", malicious)
                                    c2.metric("Suspicious", suspicious)
                                    c3.metric("Harmless", harmless)
                                    c4.metric("Undetected", undetected)

                                    # verdict
                                    if malicious > 0 or suspicious > 0:
                                        st.error("🚨 This URL is flagged by one or more vendors. See details below.")
                                    else:
                                        st.success("✅ No vendors flagged this URL as malicious/suspicious (per VT).")

                                    # Show link to full report
                                    vt_gui_link = f"https://www.virustotal.com/gui/url/{encode_url_id(url_input)}"
                                    st.markdown(f"[🔍 Open full VirusTotal report]({vt_gui_link})")

                                    # Build per-engine DataFrame
                                    if results:
                                        rows = []
                                        flagged_rows = []
                                        for engine_key, info in results.items():
                                            engine_name = info.get("engine_name") or engine_key
                                            category = info.get("category") or ""
                                            result_str = info.get("result") or ""
                                            rows.append({"engine": engine_name, "category": category, "result": result_str})
                                            if category.lower() in ("malicious", "suspicious"):
                                                flagged_rows.append({"engine": engine_name, "category": category, "result": result_str})

                                        df = pd.DataFrame(rows)
                                        flagged_df = pd.DataFrame(flagged_rows)

                                        # If any vendor flagged, show flagged list + full table and download button
                                        if not flagged_df.empty:
                                            st.subheader("🛑 Vendors that flagged this URL")
                                            st.table(flagged_df.reset_index(drop=True))

                                            st.subheader("🔎 Full per-engine results (flagged first)")
                                            # sort flagged first
                                            df["flagged_sort"] = df["category"].apply(lambda x: 0 if x and x.lower() in ("malicious", "suspicious") else 1)
                                            df = df.sort_values(["flagged_sort", "engine"]).drop(columns=["flagged_sort"]).reset_index(drop=True)
                                            st.dataframe(df, use_container_width=True)

                                            # CSV download for analysts
                                            csv_bytes = df.to_csv(index=False).encode("utf-8")
                                            st.download_button("Download results CSV", csv_bytes, file_name="vt_per_engine_results.csv", mime="text/csv")
                                        else:
                                            # no flagged vendors - offer checkbox to view full table
                                            if st.checkbox("Show per-engine results (all vendors)"):
                                                st.dataframe(df, use_container_width=True)
                                    else:
                                        st.write("No per-engine results available in the report.")
                except requests.exceptions.RequestException as e:
                    st.error(f"Network error communicating with VirusTotal: {e}")
                except Exception as e:
                    st.error(f"Unexpected error: {e}")

    # ---------------- Tab 2: AbuseIPDB ----------------
    with tab2:
        st.markdown("**Check IP/Domain reputation via AbuseIPDB.**")
        query = st.text_input("Enter IP address or domain to check (AbuseIPDB)", key="abuse_input")
        max_age = st.number_input("Max age of reports (days)", min_value=1, max_value=365, value=90, step=1)

        if st.button("🔍 Scan for Reputation", key="abuse_scan"):
            if not query or not query.strip():
                st.warning("Please enter an IP or domain.")
            elif not ABUSEIPDB_KEY:
                st.error("AbuseIPDB API key missing. Set ABUSEIPDB_API in your .env.")
            else:
                try:
                    with st.spinner("Querying AbuseIPDB..."):
                        r = abuseipdb_check(query.strip(), max_age_days=int(max_age))
                    if r.status_code != 200:
                        st.error(f"API error ({r.status_code}): {r.text}")
                    else:
                        data = r.json().get("data", {})
                        score = data.get("abuseConfidenceScore")
                        total_reports = data.get("totalReports")
                        last_reported = data.get("lastReportedAt")
                        country = data.get("countryCode")
                        isp = data.get("isp")
                        usage = data.get("usageType")

                        st.subheader("📊 Reputation Summary")
                        col1, col2, col3 = st.columns([1,1,2])
                        col1.metric("Abuse Score", f"{score}%" if score is not None else "N/A")
                        col2.metric("Total Reports", total_reports if total_reports is not None else "N/A")
                        col3.write(f"**Last Reported:** {last_reported if last_reported else 'N/A'}  \n**Country:** {country or 'N/A'}  \n**ISP:** {isp or 'N/A'}  \n**Usage Type:** {usage or 'N/A'}")

                        if score is not None and score >= 50:
                            st.error("⚠️ High abuse score — this IP/domain is likely malicious or compromised.")
                        elif score is not None and score > 0:
                            st.warning("⚠️ Some reports exist — exercise caution.")
                        else:
                            st.success("✅ No abuse reports found (within selected period).")

                   
                except requests.exceptions.RequestException as e:
                    st.error(f"Network error communicating with AbuseIPDB: {e}")
                except Exception as e:
                    st.error(f"Unexpected error: {e}")


# If you want to test this file directly:
if __name__ == "__main__":
    link_page()
