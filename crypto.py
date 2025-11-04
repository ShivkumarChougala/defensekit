import string
import streamlit as st

# Function to generate a deterministic encryption key
def generate_key():
    chars = " " + string.punctuation + string.digits + string.ascii_letters
    
    # Convert the character set string to a list of characters
    chars_list = list(chars)
    
    # Create a deterministic shuffled key by rotating the character list
    key = chars_list[1:] + chars_list[:1]
    
    # Return both the original character list and the rotated key
    return chars_list, key

# Function to encrypt a message using the encryption key
def encrypt_message(plain_text, chars, key):
    cipher_text = ""
    for letter in plain_text:
        if letter in chars:
            index = chars.index(letter)
            cipher_text += key[index]
        else:
            # Append non-encrypted characters as-is
            cipher_text += letter
    return cipher_text

# Function to decrypt an encrypted message using the encryption key
def decrypt_message(cipher_text, chars, key):
    plain_text = ""
    for letter in cipher_text:
        if letter in key:
            index = key.index(letter)
            plain_text += chars[index]
        else:
            # Append non-decrypted characters as-is
            plain_text += letter
    return plain_text

# Streamlit app
def crypto_page():
    st.title("Deterministic Encryption & Decryption")

    # Generate encryption key
    chars, key = generate_key()

    # Input field for plaintext message (encryption)
    plain_text_encrypt = st.text_input("Enter a message to encrypt:")

    # Encrypt button
    if st.button("Encrypt"):
        if plain_text_encrypt:
            cipher_text = encrypt_message(plain_text_encrypt, chars, key)
            st.success("Message Encrypted Successfully!")
            st.write(f"Original Message: {plain_text_encrypt}")
            st.write(f"Encrypted Message: {cipher_text}")

    # Input field for encrypted message (decryption)
    cipher_text_decrypt = st.text_input("Enter a message to decrypt:")

    # Decrypt button
    if st.button("Decrypt"):
        if cipher_text_decrypt:
            plain_text = decrypt_message(cipher_text_decrypt, chars, key)
            st.success("Message Decrypted Successfully!")
            st.write(f"Encrypted Message: {cipher_text_decrypt}")
            st.write(f"Decrypted Message: {plain_text}")


# st.write("---")
# st.subheader("Hi, This is Cyber Security Tool Kit :wave:")
# st.write("Welcome to the Cyber Security Tools Hub, your comprehensive resource for defending against cyber threats and safeguarding your digital assets. Explore our curated collection of powerful tools designed to enhance your security posture and stay ahead of evolving cyber risks.")
# st.subheader("Our Mission")
# st.write("At Cyber Security Tools Hub, we are dedicated to empowering individuals and organizations with the knowledge and tools needed to protect their data and privacy in an increasingly digital world. Our mission is to make cyber security accessible and understandable for everyone.")
# st.markdown("[Learn More >](https://www.zscaler.com)")

if __name__ == "__main__":
    crypto_page()
