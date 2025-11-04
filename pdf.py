import streamlit as st
import pikepdf
from tqdm import tqdm

def main_page():
    st.title("PDF Decryptor")

    # File uploader for PDF and wordlist
    pdf_file = st.file_uploader("Upload PDF File", type=["pdf"])
    wordlist_file = st.file_uploader("Upload Wordlist File", type=["txt"])

    if pdf_file is not None and wordlist_file is not None:
        passwords = [line.strip() for line in wordlist_file]

        # Iterate over passwords
        progress_bar = st.progress(0)
        for i, password in enumerate(tqdm(passwords, "Decrypting PDF")):
            try:
                # Open PDF file
                with pikepdf.open(pdf_file, password=password) as pdf:
                    # Password decrypted successfully, break out of the loop
                    st.success("[+] Password found: " + password.decode())
                    break
            except pikepdf.PasswordError as e:
                # Wrong password, continue in the loop
                st.write("Incorrect password provided: " + str(e))
                continue
            finally:
                # Update progress bar
                progress_bar.progress((i + 1) / len(passwords))

# st.write("---")
# st.subheader("Hi, This is Cyber Security Tool Kit :wave:")
# st.write("Welcome to the Cyber Security Tools Hub, your comprehensive resource for defending against cyber threats and safeguarding your digital assets. Explore our curated collection of powerful tools designed to enhance your security posture and stay ahead of evolving cyber risks.")
# st.subheader("Our Mission")
# st.write("At Cyber Security Tools Hub, we are dedicated to empowering individuals and organizations with the knowledge and tools needed to protect their data and privacy in an increasingly digital world. Our mission is to make cyber security accessible and understandable for everyone.")
# st.markdown("[Learn More >](https://www.zscaler.com)")

if __name__ == "__main__":
    main_page()
