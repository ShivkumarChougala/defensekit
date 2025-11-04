import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
import base64


def generate_key():
    """
    Generates a new encryption key.
    """
    return Fernet.generate_key()


def validate_key(key_input):
    """
    Validates if the provided key is a valid 32-byte Base64-encoded string.
    """
    try:
        # Decode the key and check its length
        key = base64.urlsafe_b64decode(key_input)
        if len(key) != 32:
            raise ValueError("Invalid key length. The decoded key must be 32 bytes.")
        return key_input.encode()  # Return the key as bytes
    except Exception:
        raise ValueError("Fernet key must be a valid 32-byte Base64-encoded string.")


def encrypt_file(file_content, key):
    """
    Encrypts the file content using the provided key.
    """
    fernet = Fernet(key)
    return fernet.encrypt(file_content)


def decrypt_file(encrypted_content, key):
    """
    Decrypts the encrypted content using the provided key.
    """
    try:
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_content)
    except InvalidToken:
        st.error("Invalid token: Unable to decrypt the file. Ensure the correct key is used.")
        return None


def page():
    st.title("File Encryptor & Decryptor")
    st.markdown("This tool allows you to encrypt and decrypt files using the **Fernet** encryption method.")

    # Upload the file
    file_to_process = st.file_uploader("Upload a file to process")

    if file_to_process:
        st.success("File uploaded successfully!")

        # Operation selection
        operation = st.radio("Select Operation", ["Encrypt", "Decrypt"])

        # Key input
        st.markdown("### Encryption Key")
        key_input = st.text_input(
            "Provide an encryption key (Base64 encoded). If empty during encryption, a new key will be generated:",
            type="password",
        )

        if st.button("Process File"):
            try:
                # Validate or generate key
                key = None
                if operation == "Decrypt":
                    if not key_input:
                        st.error("Decryption requires a valid encryption key!")
                        return
                    key = validate_key(key_input)
                else:  # Encryption
                    key = validate_key(key_input) if key_input else generate_key()

                # Encrypt or decrypt based on the operation
                file_content = file_to_process.read()
                if operation == "Encrypt":
                    encrypted_content = encrypt_file(file_content, key)

                    # Display the encrypted content and download option
                    st.subheader("Encryption Successful!")
                    st.text("Your encryption key (save it to decrypt the file):")
                    st.code(key.decode())
                    st.download_button(
                        label="Download Encrypted File",
                        data=encrypted_content,
                        file_name="encrypted_file.txt",
                    )

                elif operation == "Decrypt":
                    decrypted_content = decrypt_file(file_content, key)
                    if decrypted_content:
                        # Display the decrypted content and download option
                        st.subheader("Decryption Successful!")
                        st.download_button(
                            label="Download Decrypted File",
                            data=decrypted_content,
                            file_name="decrypted_file.txt",
                        )

            except ValueError as e:
                st.error(str(e))


# Run the app
if __name__ == "__main__":
    page()
