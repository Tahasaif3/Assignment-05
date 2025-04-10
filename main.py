import streamlit as st  # type: ignore
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet # type: ignore
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === Constants ===
DATA_FILE = 'secure_data.json'
SALT = b'secure_salt'
LOCKOUT_TIME = 60  # seconds

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_data(data, passkey):
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, passkey):
    try:
        key = generate_key(passkey)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data.encode()).decode()
    except Exception:
        st.error("Decryption failed. Please check your passkey.")
        return None

# === Main App ===
stored_data = load_data()
st.title("🔐 Secure Data Encryption App")

menu = ["Home", "Register", "Login", "Store Data", "Decrypt Data"]
choice = st.sidebar.selectbox("Select an option", menu)

# === Home ===
if choice == "Home":
    st.subheader("Welcome to the Secure Data Encryption System")
    st.write("Securely register, login, store and retrieve your data using encryption.")
    st.markdown("""
        - 🔒 Passwords are hashed using PBKDF2.
        - 🔐 Data is encrypted using Fernet symmetric encryption.
        - 🧠 Multi-user support with session tracking.
        - ⏳ Lockout after multiple failed login attempts.
    """)

# === Register ===
elif choice == "Register":
    st.subheader("Register New User")
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')
    confirm_password = st.text_input("Confirm Password", type='password')
    register_button = st.button("Register")

    if register_button:
        if not username or not password:
            st.error("Username and password are required.")
        elif password != confirm_password:
            st.error("Passwords do not match.")
        elif username in stored_data:
            st.error("Username already exists.")
        else:
            hashed_password = hash_password(password)
            stored_data[username] = {
                "password": hashed_password,
                "data": ""
            }
            save_data(stored_data)
            st.success("User registered successfully!")

# === Login ===
elif choice == "Login":
    st.subheader("Login")
    username = st.text_input("Enter your username")
    password = st.text_input("Enter your password", type='password')
    login_button = st.button("Login")

    if login_button:
        if st.session_state.failed_attempts >= 3 and time.time() - st.session_state.lockout_time < LOCKOUT_TIME:
            st.error("Too many failed attempts. Please wait a minute before trying again.")
        else:
            if username in stored_data:
                hashed_pw = stored_data[username]["password"]
                if hash_password(password) == hashed_pw:
                    st.session_state.authenticated_user = username
                    st.session_state.failed_attempts = 0
                    st.success(f"Welcome back, {username}!")
                else:
                    st.session_state.failed_attempts += 1
                    st.session_state.lockout_time = time.time()
                    st.error("Incorrect password.")
            else:
                st.error("Username not found.")

# === Store Data ===
elif choice == "Store Data":
    if st.session_state.authenticated_user:
        st.subheader("Store Encrypted Data")
        data = st.text_area("Enter the data you want to encrypt")
        passkey = st.text_input("Enter a passkey to encrypt the data", type='password')
        store_button = st.button("Encrypt and Store")

        if store_button:
            if data and passkey:
                encrypted_data = encrypt_data(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"] = encrypted_data
                save_data(stored_data)
                st.success("Your data has been encrypted and saved securely.")
            else:
                st.error("Both fields are required.")
    else:
        st.warning("Please login to store data.")

# === Decrypt Data ===
elif choice == "Decrypt Data":
    if st.session_state.authenticated_user:
        st.subheader("Decrypt Your Data")
        passkey = st.text_input("Enter your passkey to decrypt data", type='password')
        decrypt_button = st.button("Decrypt")

        if decrypt_button:
            encrypted_data = stored_data[st.session_state.authenticated_user].get("data", "")
            if encrypted_data:
                decrypted = decrypt_data(encrypted_data, passkey)
                if decrypted:
                    st.success("Decrypted Data:")
                    st.code(decrypted, language='text')
            else:
                st.error("No encrypted data found for this user.")
    else:
        st.warning("You need to log in to access this section.")

# === Logout ===
if st.session_state.authenticated_user:
    if st.button("Logout"):
        st.session_state.authenticated_user = None
        st.success("You've been logged out.")
else:
    st.info("You are not currently logged in.")

# === Footer ===
st.markdown("""
    <hr style="margin-top: 3rem; margin-bottom: 1rem;">
    <div style="text-align: center; color: gray;">
      Built with ❤️ by Taha Saif
    </div>
    """, unsafe_allow_html=True)
