import streamlit as st
import dashboard
import Email
import link
import password
import crypto
import file
import pdf
import network

# ----------------------------------------
# Session State Class
# ----------------------------------------
class SessionState:
    """Manages the active navigation state for the Streamlit app."""
    def __init__(self):
        self.current_page = "Home"


# Initialize Session State
session_state = SessionState()


# ----------------------------------------
# Main Function
# ----------------------------------------
def main():
    st.sidebar.title("🛡️ DEFToolkit")

    # Sidebar Navigation Options (Professional Naming)
    page_options = [
        "Home",
        "Network scanner",
        "Temporary Email Service",
        "Secure Password Generator",
        "Phishing Link Analyzer",
        "Text Encryption & Decryption",
        "PDF Security Tools",
        "File Encryption Manager"
    ]

    selected_page = st.sidebar.selectbox("📂 Select a Module", page_options)

    # Update session state based on selection
    if selected_page != session_state.current_page:
        session_state.current_page = selected_page

    # ----------------------------------------
    # Page Routing
    # ----------------------------------------
    if session_state.current_page == "Home":
        dashboard.home_page()

    elif session_state.current_page == "Network scanner":
        network.network_page()
        
    elif session_state.current_page == "Temporary Email Service":
        Email.email_page()


    elif session_state.current_page == "Secure Password Generator":
        password.passwordgen_page()

    elif session_state.current_page == "Phishing Link Analyzer":
        link.link_page()

    elif session_state.current_page == "Text Encryption & Decryption":
        crypto.crypto_page()

    elif session_state.current_page == "PDF Security Tools":
        pdf.main_page()
        

    elif session_state.current_page == "File Encryption Manager":
        file.page()


# ----------------------------------------
# Run Application
# ----------------------------------------
if __name__ == "__main__":
    main()
