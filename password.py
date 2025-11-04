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

# st.write("---")
# st.subheader("Hi, This is Cyber Security Tool Kit :wave:")
# st.write("Welcome to the Cyber Security Tools Hub, your comprehensive resource for defending against cyber threats and safeguarding your digital assets. Explore our curated collection of powerful tools designed to enhance your security posture and stay ahead of evolving cyber risks.")
# st.subheader("Our Mission")
# st.write("At Cyber Security Tools Hub, we are dedicated to empowering individuals and organizations with the knowledge and tools needed to protect their data and privacy in an increasingly digital world. Our mission is to make cyber security accessible and understandable for everyone.")
# st.markdown("[Learn More >](https://www.zscaler.com)")     
            

# # Run the app
if __name__ == "__main__":
    passwordgen_page()
