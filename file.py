import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import io


def page():
    """
    AES-256 Secure File Encryptor & Decryptor
    -----------------------------------------
    Encrypt or decrypt any file using AES-256-GCM with password-based key derivation (PBKDF2-HMAC-SHA256).
    This tool provides enterprise-grade encryption and a clean, professional UI.
    """

    # ============================================================
    # 🔐 Utility Functions (defined inside page for full encapsulation)
    # ============================================================

    def derive_key(password: str, salt: bytes) -> bytes:
        """Derives a 256-bit AES key from the given password using PBKDF2 (SHA-256)."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 key size
            salt=salt,
            iterations=390_000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_data(data: bytes, password: str) -> bytes:
        """Encrypts binary data using AES-256-GCM."""
        salt, iv = os.urandom(16), os.urandom(12)
        key = derive_key(password, salt)

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        ciphertext = encryptor.update(data) + encryptor.finalize()
        return salt + iv + encryptor.tag + ciphertext

    def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
        """Decrypts AES-256-GCM encrypted data."""
        try:
            salt, iv, tag, ciphertext = (
                encrypted_data[:16],
                encrypted_data[16:28],
                encrypted_data[28:44],
                encrypted_data[44:]
            )

            key = derive_key(password, salt)
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()

            return decryptor.update(ciphertext) + decryptor.finalize()

        except Exception:
            raise ValueError("Invalid password or corrupted file. Decryption failed.")

    # ============================================================
    # 🎨 Streamlit UI Layout
    # ============================================================

    st.title("🔐 AES-256 Secure File Encryptor & Decryptor")
    st.caption("Professional-grade encryption powered by AES-256-GCM + PBKDF2-HMAC-SHA256")

    uploaded_file = st.file_uploader("📁 Upload any file (image, PDF, ZIP, text, etc.)")

    if not uploaded_file:
        st.info("Please upload a file to continue.")
        return

    st.success(f"✅ File uploaded: **{uploaded_file.name}**")

    operation = st.radio("Select Operation", ["Encrypt File", "Decrypt File"], horizontal=True)
    password = st.text_input("Enter Password", type="password", placeholder="Enter a strong password")

    col1, col2 = st.columns(2)
    process_btn = col1.button("🚀 Start Processing", use_container_width=True)
    clear_btn = col2.button("🧹 Clear", use_container_width=True)

    if clear_btn:
        st.rerun()

    if process_btn:
        if not password.strip():
            st.error("⚠️ Please enter a password before continuing.")
            return

        data = uploaded_file.read()

        try:
            if operation == "Encrypt File":
                with st.spinner("🔒 Encrypting..."):
                    encrypted = encrypt_data(data, password)
                    output_name = uploaded_file.name + ".enc"
                st.success("✅ Encryption Successful!")
                st.download_button(
                    "📥 Download Encrypted File",
                    data=encrypted,
                    file_name=output_name,
                    use_container_width=True
                )

            else:  # Decrypt
                with st.spinner("🔓 Decrypting..."):
                    decrypted = decrypt_data(data, password)
                    output_name = uploaded_file.name.replace(".enc", "")
                st.success("✅ Decryption Successful!")

                # Preview if it's an image (warning-free)
                if any(output_name.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"]):
                    st.image(io.BytesIO(decrypted), caption="🖼️ Decrypted Image Preview", use_container_width=True)

                st.download_button(
                    "📥 Download Decrypted File",
                    data=decrypted,
                    file_name=output_name,
                    use_container_width=True
                )

        except ValueError as e:
            st.error(f"❌ {str(e)}")
        except Exception as e:
            st.error(f"⚠️ Unexpected error: {str(e)}")

    st.markdown("""
    ---
    **Encryption Standard:** AES-256-GCM  
    **Key Derivation:** PBKDF2-HMAC-SHA256 (390k rounds)  
    **Security:** Industry-grade | Tamper-proof | Binary-safe  
    """)


# ============================================================
# 🏁 Run this page directly (for debugging)
# ============================================================
if __name__ == "__main__":
    page()
