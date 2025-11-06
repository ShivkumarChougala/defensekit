import streamlit as st
from mailtm import Email
import threading
import time
from queue import Queue


def email_page():
    st.title("📧 Temporary Email Service")

    # Initialize session state once
    if "email_service" not in st.session_state:
        email_service = Email()
        email_service.register()
        st.session_state.email_service = email_service
        st.session_state.email_address = email_service.address
        st.session_state.email_domain = email_service.domain
        st.session_state.messages = []
        st.session_state.new_message_queue = Queue()

        # Background listener (thread-safe)
        def listener(new_msg):
            st.session_state.new_message_queue.put(new_msg)

        listener_thread = threading.Thread(
            target=email_service.start, args=(listener,), daemon=True
        )
        listener_thread.start()

    email_service = st.session_state.email_service

    st.subheader("📮 Your Temporary Email Address")
    st.text_input("Copy this email address to use anywhere:", st.session_state.email_address)
    st.caption(f"🌐 Domain: {st.session_state.email_domain}")
    st.caption("🔗 Login: https://mail.tm")

    st.divider()

    # Process new messages safely (from queue)
    while not st.session_state.new_message_queue.empty():
        msg = st.session_state.new_message_queue.get()
        st.session_state.messages.insert(0, msg)

    # Manual refresh option
    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button("🔄 Refresh Inbox"):
            try:
                msgs = email_service.get_mailbox()
                st.session_state.messages = msgs
            except Exception as e:
                st.warning(f"⚠️ Unable to refresh inbox: {e}")

    with col2:
        auto_refresh = st.checkbox("Auto Refresh every 5s", value=True)

    # Show messages
    if st.session_state.messages:
        st.success(f"📬 You have {len(st.session_state.messages)} message(s).")

        for msg in st.session_state.messages:
            subject = msg.get("subject", "No Subject")
            content = msg.get("text") or msg.get("html") or ""
            if isinstance(content, list):
                content = "\n".join(content)
            with st.expander(subject):
                st.write(content)
    else:
        st.info("No emails received yet. Wait a few seconds after registering somewhere.")

    # Auto-refresh inbox
    if auto_refresh:
        time.sleep(5)
        st.rerun()


if __name__ == "__main__":
    email_page()
