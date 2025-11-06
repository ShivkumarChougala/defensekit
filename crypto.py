import streamlit as st
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes
import base64

def crypto_page():
    st.set_page_config(page_title="Encryption & Decryption Center", page_icon="🔐", layout="wide")

    st.title("🔐 Encryption & Decryption Center")
    st.markdown(
        """
        Welcome to the **Modern Symmetric Encryption Center**.  
        Choose your encryption algorithm, encrypt or decrypt your data securely, and manage your keys safely.  
        _Ensure you store your keys securely — lost keys mean lost data!_
        """
    )

    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        algo = st.selectbox("🔧 Select Encryption Algorithm", ["Fernet (AES-128)", "AES (Advanced Encryption Standard)", "ChaCha20"])
    with col2:
        mode = st.radio("⚙️ Choose Operation", ["Encrypt", "Decrypt"])

    text = st.text_area("🧾 Enter Your Text or Ciphertext Below", height=150)

    # ------------------------------------------------------------------------- #
    # FERNET
    # ------------------------------------------------------------------------- #
    if algo == "Fernet (AES-128)":
        st.subheader("🔹 Fernet Encryption (AES-128 with Authentication)")

        if mode == "Encrypt":
            if st.button("🔒 Encrypt with Fernet"):
                try:
                    key = Fernet.generate_key()
                    f = Fernet(key)
                    encrypted = f.encrypt(text.encode())

                    st.success("✅ Encryption Successful!")
                    st.markdown("### 🔑 Encrypted Output")
                    st.code(encrypted.decode())
                    st.info("🔐 Save your key securely for decryption:")
                    st.code(key.decode())
                except Exception as e:
                    st.error(f"❌ Encryption Failed: {e}")

        elif mode == "Decrypt":
            key_input = st.text_input("🔑 Enter Your Fernet Key")
            if st.button("🔓 Decrypt Fernet"):
                try:
                    f = Fernet(key_input.encode())
                    decrypted = f.decrypt(text.encode()).decode()
                    st.success("✅ Decryption Successful!")
                    st.markdown("### 📜 Decrypted Message")
                    st.code(decrypted)
                except Exception as e:
                    st.error(f"❌ Decryption Failed: {e}")

    # ------------------------------------------------------------------------- #
    # AES (EAX Mode)
    # ------------------------------------------------------------------------- #
    elif algo == "AES (Advanced Encryption Standard)":
        st.subheader("🔹 AES Encryption (EAX Mode - Secure & Authenticated)")

        if mode == "Encrypt":
            if st.button("🔒 Encrypt with AES"):
                try:
                    key = get_random_bytes(16)
                    cipher = AES.new(key, AES.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(text.encode())

                    # Combine nonce + tag + ciphertext
                    bundle = cipher.nonce + tag + ciphertext
                    encoded_bundle = base64.b64encode(bundle).decode()
                    encoded_key = base64.b64encode(key).decode()

                    st.success("✅ AES Encryption Complete")
                    st.markdown("### 🔑 Encrypted Output")
                    st.code(encoded_bundle)
                    st.info("🔐 AES Key (Base64 Encoded):")
                    st.code(encoded_key)
                except Exception as e:
                    st.error(f"❌ Encryption Failed: {e}")

        elif mode == "Decrypt":
            key_input = st.text_input("🔑 Enter AES Key (Base64)")
            if st.button("🔓 Decrypt AES"):
                try:
                    raw = base64.b64decode(text.strip())
                    key = base64.b64decode(key_input.strip())

                    # Split into nonce, tag, ciphertext
                    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]

                    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                    decrypted = cipher.decrypt_and_verify(ciphertext, tag).decode()

                    st.success("✅ Decryption Successful!")
                    st.markdown("### 📜 Decrypted Text")
                    st.code(decrypted)
                except Exception as e:
                    st.error(f"❌ Decryption Failed: {e}")

    # ------------------------------------------------------------------------- #
    # CHACHA20
    # ------------------------------------------------------------------------- #
    elif algo == "ChaCha20":
        st.subheader("🔹 ChaCha20 Stream Cipher (Fast & Modern)")

        if mode == "Encrypt":
            if st.button("🔒 Encrypt with ChaCha20"):
                try:
                    key = get_random_bytes(32)
                    cipher = ChaCha20.new(key=key)
                    ciphertext = cipher.nonce + cipher.encrypt(text.encode())

                    encoded_cipher = base64.b64encode(ciphertext).decode()
                    encoded_key = base64.b64encode(key).decode()

                    st.success("✅ ChaCha20 Encryption Complete")
                    st.markdown("### 🔑 Encrypted Data")
                    st.code(encoded_cipher)
                    st.info("🔐 ChaCha20 Key (Base64 Encoded):")
                    st.code(encoded_key)
                except Exception as e:
                    st.error(f"❌ Encryption Failed: {e}")

        elif mode == "Decrypt":
            key_input = st.text_input("🔑 Enter ChaCha20 Key (Base64)")
            if st.button("🔓 Decrypt ChaCha20"):
                try:
                    data = base64.b64decode(text.strip())
                    key = base64.b64decode(key_input.strip())

                    nonce, ciphertext = data[:8], data[8:]
                    cipher = ChaCha20.new(key=key, nonce=nonce)
                    decrypted = cipher.decrypt(ciphertext).decode()

                    st.success("✅ Decryption Successful!")
                    st.markdown("### 📜 Decrypted Message")
                    st.code(decrypted)
                except Exception as e:
                    st.error(f"❌ Decryption Failed: {e}")

    st.divider()
    st.caption("🧠 Tip: Always store your encryption keys securely — without the key, your encrypted data cannot be recovered.")
