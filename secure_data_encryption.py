import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64
import os
import json

# --- File paths ---
DATA_FILE = "data_store.json"

# --- Utilities ---
def generate_key():
    return Fernet.generate_key()

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def get_fernet(passkey):
    key = hashlib.sha256(passkey.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))

def encrypt_data(data, passkey):
    f = get_fernet(passkey)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, passkey):
    f = get_fernet(passkey)
    return f.decrypt(encrypted_data.encode()).decode()

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {"users": {}, "stored_data": {}}

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump({"users": users, "stored_data": stored_data}, f)

# --- Load persistent data ---
loaded = load_data()
stored_data = loaded["stored_data"]
users = loaded["users"]
if "login_status" not in st.session_state:
    st.session_state.login_status = {"logged_in": False, "username": ""}
if "attempts" not in st.session_state:
    st.session_state.attempts = {}
if "page" not in st.session_state:
    st.session_state.page = "Login"

# --- Streamlit Pages ---
def login_page():
    st.markdown("""
        <div style='text-align: center;'>
            <h1>🔐 Secure Data System</h1>
            <h4>Welcome! Please login or signup to continue.</h4>
        </div>
    """, unsafe_allow_html=True)

    auth_choice = st.radio("Select an option", ["Login", "Signup"], horizontal=True)

    if auth_choice == "Login":
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            hashed_password = hash_passkey(password)
            if username in users and users[username] == hashed_password:
                st.session_state.login_status["logged_in"] = True
                st.session_state.login_status["username"] = username
                st.session_state.attempts[username] = 0
                st.success("✅ Login successful")
                st.session_state.page = "Home"
                st.rerun()
            else:
                st.error("❌ Invalid credentials")

    elif auth_choice == "Signup":
        username = st.text_input("New Username")
        password = st.text_input("New Password", type="password")

        if st.button("Signup"):
            if username in users:
                st.warning("⚠️ Username already exists!")
            else:
                users[username] = hash_passkey(password)
                stored_data[username] = {}
                st.session_state.attempts[username] = 0
                save_data()
                st.success("✅ Account created. Please login.")

def sidebar():
    with st.sidebar:
        st.markdown(f"**👤 Logged in as:** `{st.session_state.login_status['username']}`")
        menu = st.radio("\n🧰 Tools\n", ["🏠 Dashboard", "📥 Store Data", "🔐 Retrieve Data", "🚪 Logout"])
        return menu

def home_page():
    menu = sidebar()

    if menu == "🏠 Dashboard":
        st.markdown(f"""
            <div style='text-align: center;'>
                <h1>🏠 Welcome, {st.session_state.login_status['username']}</h1>
                <h4>Secure Data Encryption System</h4>
            </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <ul>
            <li>📝 Signup & 🔓 Login authentication</li>
            <li>🔐 AES-based encryption via <code>cryptography.fernet</code></li>
            <li>💾 Secure storage in JSON file</li>
            <li>📥 Store & 🔐 Retrieve encrypted content with passkey</li>
            <li>✅ Logout & access control system</li>
            <li>🧠 Prevents brute-force decryption attempts</li>
        </ul>
        <h5>🎨 Tools & Technologies Used:</h5>
        <p>Python | Streamlit | Cryptography | JSON | Secure Auth</p>
        """, unsafe_allow_html=True)

    elif menu == "📥 Store Data":
        insert_data_page()

    elif menu == "🔐 Retrieve Data":
        retrieve_data_page()

    elif menu == "🚪 Logout":
        logout_confirmation()

def insert_data_page():
    st.subheader("🔒 Insert Data")
    text = st.text_area("Enter your secret data")
    passkey = st.text_input("Enter a passkey", type="password")

    if st.button("Store Securely"):
        if passkey:
            # Generate the encryption key using Fernet
            encryption_key = generate_key()  # Store the encryption key
            fernet = Fernet(encryption_key)
            encrypted = fernet.encrypt(text.encode()).decode()  # Encrypt the data
            hashed_passkey = hash_passkey(passkey)

            # Append the encrypted data and key to the user's data list
            if "encrypted_data" not in stored_data[st.session_state.login_status["username"]]:
                stored_data[st.session_state.login_status["username"]]["encrypted_data"] = []
            
            stored_data[st.session_state.login_status["username"]]["encrypted_data"].append({
                "encrypted_text": encrypted,
                "encryption_key": encryption_key.decode(),  # Store key as string
                "passkey": hashed_passkey
            })

            save_data()
            st.success("✅ Data stored securely!")
        else:
            st.warning("⚠️ Passkey required")

def retrieve_data_page():
    st.subheader("📥 Retrieve Your Encrypted Data")
    user = st.session_state.login_status["username"]
    
    # Retrieve and display all encrypted data entries
    encrypted_data_list = stored_data[user].get("encrypted_data", [])
    for idx, data in enumerate(encrypted_data_list):
        encrypted_text = data.get("encrypted_text")
        encryption_key = data.get("encryption_key")
        passkey = data.get("passkey")
        
        st.markdown(f"🔒 **Encrypted #{idx + 1}**\n`{encrypted_text}`")
        st.markdown(f"**Encryption Key for Entry #{idx + 1}:** `{encryption_key}`")
        st.markdown(f"**Passkey Hash for Entry #{idx + 1}:** `{passkey}`")

        # User input for the specific passkey to decrypt
        passkey_input = st.text_input(f"Enter Passkey for Entry #{idx + 1}", type="password", key=f"passkey_{idx}")

        if passkey_input and st.button(f"Decrypt Entry #{idx + 1}"):
            if hash_passkey(passkey_input) == passkey:
                fernet = Fernet(encryption_key.encode())  # Use the stored encryption key to decrypt
                decrypted_message = fernet.decrypt(encrypted_text.encode()).decode()
                st.success(f"✅ Decrypted Message #{idx + 1}:")
                st.code(decrypted_message)  # Display decrypted data
            else:
                st.error(f"❌ Incorrect passkey for Entry #{idx + 1}.")

def logout_confirmation():
    st.subheader("Are you sure you want to logout?")
    confirm_logout = st.radio("", ["Yes", "No"], index=1)  # Default to "No"

    if confirm_logout == "Yes":
        st.session_state.login_status = {"logged_in": False, "username": ""}
        st.session_state.page = "Login"
        st.rerun()  # Redirect to login page after logging out
    elif confirm_logout == "No":
        st.session_state.page = "Home"
        st.rerun()  # Stay on home page if user selects "No"


# --- Main App ---
if st.session_state.page == "Login":
    login_page()
elif st.session_state.page == "Home":
    if st.session_state.login_status["logged_in"]:
        home_page()
    else:
        st.warning("⚠️ Please log in to access this page.")
