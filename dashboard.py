import streamlit as st
import requests
from streamlit_lottie import st_lottie
import os

def home_page():
   
    st.set_page_config(
        page_title="DEFToolkit",
        page_icon="💀",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # ---------- helpers ----------
    def load_lottieurl(url: str, timeout: int = 6):
        """Load a Lottie animation from a URL and return JSON or None."""
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200:
                return r.json()
        except Exception:
            return None
        return None

    def load_local_css(path: str = "assets/style.css"):
        """Inject local CSS file into the page (if present)."""
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

    # Inject CSS for hacker-horror theme
    load_local_css("assets/style.css")

    # background overlay (keeps CSS-driven background visible)
    st.markdown('<div class="bg-veil"></div>', unsafe_allow_html=True)

    # ---------- layout ----------
    left_col, right_col = st.columns([1.6, 1])

    # Left: Title + mission + details (terminal box)
    with left_col:
        st.markdown('<div class="hh-title">DEFTOOLKIT</div>', unsafe_allow_html=True)
        st.markdown('<div class="hh-sub">Toolkit · Recon · Encryption · Forensics</div>', unsafe_allow_html=True)
        st.markdown("<div class='sep'></div>", unsafe_allow_html=True)

        st.markdown(
            """
            <div class="hh-terminal">
                <div class="hh-term-header">▣ MISSION</div>
                <div class="hh-term-body">
                Welcome to the Cyber Security Toolkit — your modular lab for threat analysis,
                secure file handling, and rapid reconnaissance. Built for learning, auditing,
                and safe experimentation. Proceed responsibly.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            """
            <div class="hh-terminal small">
                <div class="hh-term-header">▣ MODULES</div>
                <div class="hh-term-body">
                • Network Scanner e<br/>
                • Phishing Link Analyzer<br/>
                • Text Encryption & Decryption<br/>
                • PDF Security Tools<br/>
                • Temporary Email Service<br/>
                • File Encryption Manager<br/>
                • Secure Password Generator<br/>
            
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.write("---")
        st.markdown("### Project overview")
        st.write(
            "This toolkit demonstrates defensive and educational security techniques. Use tools only "
            "on systems you own or have explicit permission to test."
        )
        st.write("---")
 # Footer / disclaimer (small) with email + links
    st.markdown(
        """
        <div class="hh-footer">
            <div class="hh-footer-left">© 2025 DEFToolKIT</div>
            <div class="hh-footer-center">⚠️ Use responsibly — educational purposes only.</div>
            <div class="hh-footer-right">
                <a href="mailto:youremail@example.com" class="footer-link">📧 an0th3rh4ck.com</a>
                &nbsp; • &nbsp;
                <a href="https://github.com/ShivkumarChougala" target="_blank" class="footer-link">💻 GitHub</a>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # if navigation buttons were pressed, let easy.py handle it via session_state
    if st.session_state.get("navigate_to"):
        # leave value for easy.py to read and route
        st.experimental_rerun()

    # Right: Animation + quick links / small widgets
    with right_col:
        st.markdown("<div class='right-panel'>", unsafe_allow_html=True)

        lottie = load_lottieurl("https://assets5.lottiefiles.com/packages/lf20_fcfjwiyb.json")
        if lottie:
            st_lottie(lottie, height=300, key="hero_hh")
        else:
            st.markdown("<div class='muted small'>Animation unavailable</div>", unsafe_allow_html=True)

        st.markdown("<div class='sep-small'></div>", unsafe_allow_html=True)

        st.markdown("<div class='links-head'>QUICK LINKS</div>", unsafe_allow_html=True)
        st.markdown(
            """
            <ul class='hh-links'>
                <li><a href='https://github.com/ShivkumarChougala/defensekit/' target='_blank'>Project Repo</a></li>
                <li><a href='https://www.owasp.org/' target='_blank'>OWASP Guides</a></li>
                <li><a href='' target='_blank'>Learn More</a></li>
            </ul>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

   
