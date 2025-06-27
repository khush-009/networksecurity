import streamlit as st
import requests
import pandas as pd

# FastAPI backend URL
BACKEND_URL = "http://localhost:8000"

st.set_page_config(page_title="Phishing URL Detection", layout="centered")

st.title("🔐 Phishing URL Detector")
st.write("Enter a URL or upload a CSV file to check for phishing threats.")

# --- Option 1: Predict a Single URL ---
st.subheader("🔗 Single URL Prediction")
url_input = st.text_input("Enter a URL", placeholder="e.g. http://example.com")

if st.button("Predict"):
    if url_input:
        with st.spinner("Predicting..."):
            try:
                response = requests.post(
                    f"{BACKEND_URL}/predict-url",
                    data={"url": url_input}
                )
                if response.status_code == 200:
                    result = response.json()
                    st.success(f"Prediction for {result['url']}: {result['prediction']}")
                else:
                    st.error(f"API Error: {response.status_code}")
            except Exception as e:
                st.error(f"Request failed: {e}")
    else:
        st.warning("Please enter a URL.")

# --- Option 2: Batch Prediction using CSV ---
st.subheader("📄 Batch URL Prediction via CSV")
st.markdown("CSV must contain feature columns (like those in your training data).")

csv_file = st.file_uploader("Upload CSV", type=["csv"])

if csv_file is not None:
    if st.button("Upload and Predict"):
        with st.spinner("Uploading and predicting..."):
            try:
                response = requests.post(
                    f"{BACKEND_URL}/predict-csv",
                    files={"file": csv_file.getvalue()}
                )
                if response.status_code == 200:
                    result = response.json()
                    st.success(result["message"])
                    st.markdown("✅ Output saved as `output.csv` on the backend.")
                else:
                    st.error(f"API Error: {response.status_code}")
            except Exception as e:
                st.error(f"Request failed: {e}")
