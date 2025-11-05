import random
import string
import pyperclip
import streamlit as st


def generate_password(length, use_uppercase, use_numbers, use_special_chars):
    characters = string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_numbers:
        characters += string.digits
    if use_special_chars:
        characters += string.punctuation

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def passwordgen_page():
    st.title("Password Generator")

    # Password length input
    length = st.slider("Select password length:", 8, 32, 12)

    # Checkbox inputs
    use_uppercase = st.checkbox("Include Uppercase Letters")
    use_numbers = st.checkbox("Include Numbers")
    use_special_chars = st.checkbox("Include Special Characters")

    # Generate button
    if st.button("Generate Password"):
        password = generate_password(length, use_uppercase, use_numbers, use_special_chars)
        st.success("Generated Password:")
        st.write(password)

        # Copy to Clipboard button
        copy_button_label = "Copy to Clipboard"
        if st.button(copy_button_label):
            pyperclip.copy(password)
            st.info("Password copied to clipboard!")



# # Run the app
if __name__ == "__main__":
    passwordgen_page()
