import streamlit as st
import requests
from bs4 import BeautifulSoup


def link_page():
    def scan_phishing(url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            title = soup.title.string
            return title
        except Exception as e:
            return str(e)

    st.title("Phishing Link Scanner")

    url = st.text_input("Enter URL to Scan")
    if st.button("Scan"):
        if url:
            st.write("Scanning URL:", url)
            title = scan_phishing(url)
            st.write("Title of the Webpage:", title)
        else:
            st.write("Please enter a URL to scan.")
# st.write("---")
# st.subheader("Hi, This is Cyber Security Tool Kit :wave:")
# st.write("Welcome to the Cyber Security Tools Hub, your comprehensive resource for defending against cyber threats and safeguarding your digital assets. Explore our curated collection of powerful tools designed to enhance your security posture and stay ahead of evolving cyber risks.")
# st.subheader("Our Mission")
# st.write("At Cyber Security Tools Hub, we are dedicated to empowering individuals and organizations with the knowledge and tools needed to protect their data and privacy in an increasingly digital world. Our mission is to make cyber security accessible and understandable for everyone.")
# st.markdown("[Learn More >](https://www.zscaler.com)")