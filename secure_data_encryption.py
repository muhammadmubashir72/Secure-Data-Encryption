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


# import streamlit as st
# import hashlib
# from cryptography.fernet import Fernet
# import base64
# import os
# import json

# # --- File paths ---
# DATA_FILE = "data_store.json"

# # --- Utilities ---
# def generate_key():
#     return Fernet.generate_key()

# def hash_passkey(passkey):
#     return hashlib.sha256(passkey.encode()).hexdigest()

# def get_fernet(passkey):
#     key = hashlib.sha256(passkey.encode()).digest()
#     return Fernet(base64.urlsafe_b64encode(key))

# def encrypt_data(data, passkey):
#     f = get_fernet(passkey)
#     return f.encrypt(data.encode()).decode()

# def decrypt_data(encrypted_data, passkey):
#     f = get_fernet(passkey)
#     return f.decrypt(encrypted_data.encode()).decode()

# def load_data():
#     if os.path.exists(DATA_FILE):
#         with open(DATA_FILE, "r") as f:
#             return json.load(f)
#     return {"users": {}, "stored_data": {}}

# def save_data():
#     with open(DATA_FILE, "w") as f:
#         json.dump({"users": users, "stored_data": stored_data}, f)

# # --- Load persistent data ---
# loaded = load_data()
# stored_data = loaded["stored_data"]
# users = loaded["users"]
# if "login_status" not in st.session_state:
#     st.session_state.login_status = {"logged_in": False, "username": ""}
# if "attempts" not in st.session_state:
#     st.session_state.attempts = {}
# if "page" not in st.session_state:
#     st.session_state.page = "Login"

# # --- Streamlit Pages ---
# def login_page():
#     st.markdown("""
#         <div style='text-align: center;'>
#             <h1>🔐 Secure Data System</h1>
#             <h4>Welcome! Please login or signup to continue.</h4>
#         </div>
#     """, unsafe_allow_html=True)

#     auth_choice = st.radio("Select an option", ["Login", "Signup"], horizontal=True)

#     if auth_choice == "Login":
#         username = st.text_input("Username")
#         password = st.text_input("Password", type="password")

#         if st.button("Login"):
#             hashed_password = hash_passkey(password)
#             if username in users and users[username] == hashed_password:
#                 st.session_state.login_status["logged_in"] = True
#                 st.session_state.login_status["username"] = username
#                 st.session_state.attempts[username] = 0
#                 st.success("✅ Login successful")
#                 st.session_state.page = "Home"
#                 st.rerun()
#             else:
#                 st.error("❌ Invalid credentials")

#     elif auth_choice == "Signup":
#         username = st.text_input("New Username")
#         password = st.text_input("New Password", type="password")

#         if st.button("Signup"):
#             if username in users:
#                 st.warning("⚠️ Username already exists!")
#             else:
#                 users[username] = hash_passkey(password)
#                 stored_data[username] = {}
#                 st.session_state.attempts[username] = 0
#                 save_data()
#                 st.success("✅ Account created. Please login.")

# def sidebar():
#     with st.sidebar:
#         st.markdown(f"**👤 Logged in as:** `{st.session_state.login_status['username']}`")
#         menu = st.radio("\n🧰 Tools\n", ["🏠 Dashboard", "📥 Store Data", "🔐 Retrieve Data", "🚪 Logout"])
#         return menu

# def home_page():
#     menu = sidebar()

#     if menu == "🏠 Dashboard":
#         st.markdown(f"""
#             <div style='text-align: center;'>
#                 <h1>🏠 Welcome, {st.session_state.login_status['username']}</h1>
#                 <h4>Secure Data Encryption System</h4>
#             </div>
#         """, unsafe_allow_html=True)

#         st.markdown("""
#         <ul>
#             <li>📝 Signup & 🔓 Login authentication</li>
#             <li>🔐 AES-based encryption via <code>cryptography.fernet</code></li>
#             <li>💾 Secure storage in JSON file</li>
#             <li>📥 Store & 🔐 Retrieve encrypted content with passkey</li>
#             <li>✅ Logout & access control system</li>
#             <li>🧠 Prevents brute-force decryption attempts</li>
#         </ul>
#         <h5>🎨 Tools & Technologies Used:</h5>
#         <p>Python | Streamlit | Cryptography | JSON | Secure Auth</p>
#         """, unsafe_allow_html=True)

#     elif menu == "📥 Store Data":
#         insert_data_page()

#     elif menu == "🔐 Retrieve Data":
#         retrieve_data_page()

#     elif menu == "🚪 Logout":
#         logout_confirmation()

# def insert_data_page():
#     st.subheader("🔒 Insert Data")
#     text = st.text_area("Enter your secret data")
#     passkey = st.text_input("Enter a passkey", type="password")

#     if st.button("Store Securely"):
#         if passkey:
#             # Generate the encryption key using Fernet
#             encryption_key = generate_key()  # Store the encryption key
#             fernet = Fernet(encryption_key)
#             encrypted = fernet.encrypt(text.encode()).decode()  # Encrypt the data
#             hashed_passkey = hash_passkey(passkey)

#             # Store the encrypted data and the key
#             stored_data[st.session_state.login_status["username"]]["encrypted_text"] = encrypted
#             stored_data[st.session_state.login_status["username"]]["passkey"] = hashed_passkey
#             stored_data[st.session_state.login_status["username"]]["encryption_key"] = encryption_key.decode()  # Store key as string

#             save_data()
#             st.success("✅ Data stored securely!")
#             # st.markdown(f"**Encryption Key Used:** `{encryption_key.decode()}`")  # Display the encryption key
#         else:
#             st.warning("⚠️ Passkey required")

# def retrieve_data_page():
#     st.subheader("📥 Retrieve Your Encrypted Data")
#     user = st.session_state.login_status["username"]
#     passkey = st.text_input("Enter Passkey for #1", type="password")

#     encrypted_data = stored_data[user].get("encrypted_text")
#     encryption_key = stored_data[user].get("encryption_key")

#     # Show the encrypted data and key for user reference
#     if encrypted_data:
#         st.markdown(f"🔒 **Encrypted #1**\n`{encrypted_data}`")

#     if encryption_key:
#         st.markdown(f"**Encryption Key Used:** `{encryption_key}`")

#     if st.button("Decrypt Data"):
#         if st.session_state.attempts.get(user, 0) >= 3:
#             st.warning("🚫 Too many failed attempts. Please sign in again.")
#             st.session_state.login_status["logged_in"] = False
#             st.session_state.page = "Login"
#             st.rerun()
#             return

#         hashed_passkey = hash_passkey(passkey)  # Hash the passkey entered by the user

#         # Display the encrypted data before decryption
#         if hashed_passkey == stored_data[user].get("passkey"):
#             fernet = Fernet(encryption_key.encode())  # Use the stored encryption key to decrypt
#             decrypted_message = fernet.decrypt(stored_data[user]["encrypted_text"].encode()).decode()
#             st.success("✅ Decrypted Message:")
#             st.code(decrypted_message)  # Display decrypted data
#             st.session_state.attempts[user] = 0
#         else:
#             st.session_state.attempts[user] = st.session_state.attempts.get(user, 0) + 1
#             st.error(f"❌ Incorrect passkey. Attempt {st.session_state.attempts[user]} of 3")

# def logout_confirmation():
#     confirm_logout = st.radio("Are you sure you want to logout?", ["No", "Yes"])

#     if confirm_logout == "Yes":
#         st.session_state.login_status = {"logged_in": False, "username": ""}
#         st.session_state.page = "Login"
#         st.rerun()
#     elif confirm_logout == "No":
#         st.session_state.page = "Home"
#         st.rerun()

# # --- Main App ---
# if st.session_state.page == "Login":
#     login_page()
# elif st.session_state.page == "Home":
#     if st.session_state.login_status["logged_in"]:
#         home_page()
#     else:
#         st.warning("⚠️ Please log in to access this page.")

# import streamlit as st
# import hashlib
# from cryptography.fernet import Fernet
# import base64
# import os
# import json

# # --- File paths ---
# DATA_FILE = "data_store.json"

# # --- Utilities ---
# def generate_key():
#     return Fernet.generate_key()

# def hash_passkey(passkey):
#     return hashlib.sha256(passkey.encode()).hexdigest()

# def get_fernet(passkey):
#     key = hashlib.sha256(passkey.encode()).digest()
#     return Fernet(base64.urlsafe_b64encode(key))

# def encrypt_data(data, passkey):
#     f = get_fernet(passkey)
#     return f.encrypt(data.encode()).decode()

# def decrypt_data(encrypted_data, passkey):
#     f = get_fernet(passkey)
#     return f.decrypt(encrypted_data.encode()).decode()

# def load_data():
#     if os.path.exists(DATA_FILE):
#         with open(DATA_FILE, "r") as f:
#             return json.load(f)
#     return {"users": {}, "stored_data": {}}

# def save_data():
#     with open(DATA_FILE, "w") as f:
#         json.dump({"users": users, "stored_data": stored_data}, f)

# # --- Load persistent data ---
# loaded = load_data()
# stored_data = loaded["stored_data"]
# users = loaded["users"]
# if "login_status" not in st.session_state:
#     st.session_state.login_status = {"logged_in": False, "username": ""}
# if "attempts" not in st.session_state:
#     st.session_state.attempts = {}
# if "page" not in st.session_state:
#     st.session_state.page = "Login"

# # --- Streamlit Pages ---
# def login_page():
#     st.markdown("""
#         <div style='text-align: center;'>
#             <h1>🔐 Secure Data System</h1>
#             <h4>Welcome! Please login or signup to continue.</h4>
#         </div>
#     """, unsafe_allow_html=True)

#     auth_choice = st.radio("Select an option", ["Login", "Signup"], horizontal=True)

#     if auth_choice == "Login":
#         username = st.text_input("Username")
#         password = st.text_input("Password", type="password")

#         if st.button("Login"):
#             hashed_password = hash_passkey(password)
#             if username in users and users[username] == hashed_password:
#                 st.session_state.login_status["logged_in"] = True
#                 st.session_state.login_status["username"] = username
#                 st.session_state.attempts[username] = 0
#                 st.success("✅ Login successful")
#                 st.session_state.page = "Home"
#                 st.rerun()
#             else:
#                 st.error("❌ Invalid credentials")

#     elif auth_choice == "Signup":
#         username = st.text_input("New Username")
#         password = st.text_input("New Password", type="password")

#         if st.button("Signup"):
#             if username in users:
#                 st.warning("⚠️ Username already exists!")
#             else:
#                 users[username] = hash_passkey(password)
#                 stored_data[username] = {}
#                 st.session_state.attempts[username] = 0
#                 save_data()
#                 st.success("✅ Account created. Please login.")


# def sidebar():
#     with st.sidebar:
#         st.markdown(f"**👤 Logged in as:** `{st.session_state.login_status['username']}`")
#         menu = st.radio("\n🧰 Tools\n", ["🏠 Dashboard", "📥 Store Data", "🔐 Retrieve Data", "🚪 Logout"])
#         return menu

# def home_page():
#     menu = sidebar()

#     if menu == "🏠 Dashboard":
#         st.markdown(f"""
#             <div style='text-align: center;'>
#                 <h1>🏠 Welcome, {st.session_state.login_status['username']}</h1>
#                 <h4>Secure Data Encryption System</h4>
#             </div>
#         """, unsafe_allow_html=True)

#         st.markdown("""
#         <ul>
#             <li>📝 Signup & 🔓 Login authentication</li>
#             <li>🔐 AES-based encryption via <code>cryptography.fernet</code></li>
#             <li>💾 Secure storage in JSON file</li>
#             <li>📥 Store & 🔐 Retrieve encrypted content with passkey</li>
#             <li>✅ Logout & access control system</li>
#             <li>🧠 Prevents brute-force decryption attempts</li>
#         </ul>
#         <h5>🎨 Tools & Technologies Used:</h5>
#         <p>Python | Streamlit | Cryptography | JSON | Secure Auth</p>
#         """, unsafe_allow_html=True)

#     elif menu == "📥 Store Data":
#         insert_data_page()

#     elif menu == "🔐 Retrieve Data":
#         retrieve_data_page()

#     elif menu == "🚪 Logout":
#         st.session_state.login_status = {"logged_in": False, "username": ""}
#         st.session_state.page = "Login"
#         st.rerun()

# def insert_data_page():
#     st.subheader("🔒 Insert Data")
#     text = st.text_area("Enter your secret data")
#     passkey = st.text_input("Enter a passkey", type="password")

#     if st.button("Store Securely"):
#         if passkey:
#             encrypted = encrypt_data(text, passkey)
#             hashed = hash_passkey(passkey)
#             stored_data[st.session_state.login_status["username"]]["encrypted_text"] = encrypted
#             stored_data[st.session_state.login_status["username"]]["passkey"] = hashed
#             save_data()
#             st.success("✅ Data stored securely!")
#         else:
#             st.warning("⚠️ Passkey required")

# def retrieve_data_page():
#     st.subheader("🔓 Retrieve Data")
#     passkey = st.text_input("Enter your passkey", type="password")

#     if st.button("Decrypt"):
#         user = st.session_state.login_status["username"]
#         if st.session_state.attempts.get(user, 0) >= 3:
#             st.warning("🚫 Too many failed attempts. Please re-login.")
#             st.session_state.login_status["logged_in"] = False
#             st.session_state.page = "Login"
#             st.rerun()
#             return

#         if hash_passkey(passkey) == stored_data[user].get("passkey"):
#             decrypted = decrypt_data(stored_data[user]["encrypted_text"], passkey)
#             st.success("✅ Decrypted Text:")
#             st.code(decrypted)
#             st.session_state.attempts[user] = 0
#         else:
#             st.session_state.attempts[user] = st.session_state.attempts.get(user, 0) + 1
#             st.error(f"❌ Incorrect passkey. Attempt {st.session_state.attempts[user]} of 3")

# # --- Main App ---
# if st.session_state.page == "Login":
#     login_page()
# elif st.session_state.page == "Home":
#     if st.session_state.login_status["logged_in"]:
#         home_page()
#     else:
#         st.warning("⚠️ Please log in to access this page.")

# import streamlit as st
# import hashlib
# import base64
# import json
# from cryptography.fernet import Fernet
# import time

# # Initialize session state variables if they don't exist
# if 'stored_data' not in st.session_state:
#     st.session_state.stored_data = {} 
# if 'failed_attempts' not in st.session_state:
#     st.session_state.failed_attempts = 0
# if 'locked_out' not in st.session_state:
#     st.session_state.locked_out = False
# if 'current_page' not in st.session_state:
#     st.session_state.current_page = 'home'
# if 'authenticated' not in st.session_state:
#     st.session_state.authenticated = True

# # Function to generate a key from a passkey
# def generate_key(passkey):
#     # Use the passkey to create a consistent key for encryption/decryption
#     key_material = hashlib.sha256(passkey.encode()).digest()
#     # Fernet requires a 32-byte URL-safe base64-encoded key
#     return base64.urlsafe_b64encode(key_material)

# # Function to hash a passkey
# def hash_passkey(passkey):
#     return hashlib.sha256(passkey.encode()).hexdigest()

# # Function to encrypt data
# def encrypt_data(data, passkey):
#     key = generate_key(passkey)
#     cipher = Fernet(key)
#     encrypted_data = cipher.encrypt(data.encode())
#     return encrypted_data

# # Function to decrypt data
# def decrypt_data(encrypted_data, passkey):
#     try:
#         key = generate_key(passkey)
#         cipher = Fernet(key)
#         decrypted_data = cipher.decrypt(encrypted_data).decode()
#         return decrypted_data
#     except Exception:
#         return None

# # Function to navigate to a page
# def navigate_to(page):
#     st.session_state.current_page = page

# # Function to check authentication and handle failed attempts
# def check_auth(passkey, stored_hash):
#     if hash_passkey(passkey) == stored_hash:
#         st.session_state.failed_attempts = 0
#         return True
#     else:
#         st.session_state.failed_attempts += 1
#         if st.session_state.failed_attempts >= 3:
#             st.session_state.locked_out = True
#             st.session_state.authenticated = False
#         return False

# # Home Page
# def home_page():
#     st.title("Secure Data Encryption System")
#     st.write("Welcome to the secure data storage and retrieval system.")
    
#     col1, col2 = st.columns(2)
#     with col1:
#         if st.button("Store New Data", use_container_width=True):
#             navigate_to('insert')
#     with col2:
#         if st.button("Retrieve Data", use_container_width=True):
#             navigate_to('retrieve')

# # Insert Data Page
# def insert_data_page():
#     st.title("Store Encrypted Data")
    
#     # Back button
#     if st.button("← Back to Home"):
#         navigate_to('home')
    
#     st.write("Enter your data and a passkey to securely store it.")
    
#     # Form for data input
#     with st.form("insert_form"):
#         data_id = st.text_input("Data ID (for retrieval later)")
#         data = st.text_area("Data to encrypt")
#         passkey = st.text_input("Passkey", type="password")
#         confirm_passkey = st.text_input("Confirm Passkey", type="password")
        
#         submitted = st.form_submit_button("Store Data")
        
#         if submitted:
#             if not data_id or not data or not passkey:
#                 st.error("All fields are required.")
#             elif passkey != confirm_passkey:
#                 st.error("Passkeys do not match.")
#             elif data_id in st.session_state.stored_data:
#                 st.error(f"Data ID '{data_id}' already exists. Please use a different ID.")
#             else:
#                 # Encrypt and store the data
#                 encrypted_data = encrypt_data(data, passkey)
#                 hashed_passkey = hash_passkey(passkey)
                
#                 st.session_state.stored_data[data_id] = {
#                     "encrypted_text": encrypted_data,
#                     "passkey": hashed_passkey
#                 }
                
#                 st.success(f"Data stored successfully with ID: {data_id}")
#                 st.info("Remember your passkey! It cannot be recovered if lost.")

# # Retrieve Data Page
# def retrieve_data_page():
#     st.title("Retrieve Encrypted Data")
    
#     # Back button
#     if st.button("← Back to Home"):
#         navigate_to('home')
    
#     st.write("Enter your Data ID and passkey to retrieve your data.")
    
#     # Display failed attempts warning
#     if st.session_state.failed_attempts > 0:
#         st.warning(f"Failed attempts: {st.session_state.failed_attempts}/3")
    
#     # Form for data retrieval
#     with st.form("retrieve_form"):
#         data_id = st.text_input("Data ID")
#         passkey = st.text_input("Passkey", type="password")
        
#         submitted = st.form_submit_button("Retrieve Data")
        
#         if submitted:
#             if not data_id or not passkey:
#                 st.error("All fields are required.")
#             elif data_id not in st.session_state.stored_data:
#                 st.error(f"No data found with ID: {data_id}")
#             else:
#                 stored_item = st.session_state.stored_data[data_id]
                
#                 # Check if passkey is correct
#                 if check_auth(passkey, stored_item["passkey"]):
#                     # Decrypt and display the data
#                     decrypted_data = decrypt_data(stored_item["encrypted_text"], passkey)
#                     if decrypted_data:
#                         st.success("Data retrieved successfully!")
#                         st.code(decrypted_data)
#                     else:
#                         st.error("Failed to decrypt data. Please check your passkey.")
#                         # This shouldn't happen if the auth check passed, but just in case
#                 else:
#                     st.error("Incorrect passkey.")
                    
#                     if st.session_state.locked_out:
#                         st.error("Too many failed attempts. Please reauthorize.")
#                         time.sleep(1)  # Brief delay before redirect
#                         navigate_to('login')

# # Login Page (for reauthorization)
# def login_page():
#     st.title("Reauthorization Required")
#     st.write("You've had too many failed attempts. Please log in to continue.")
    
#     with st.form("login_form"):
#         username = st.text_input("Username")
#         password = st.text_input("Password", type="password")
        
#         submitted = st.form_submit_button("Login")
        
#         if submitted:
#             if username and password:  # Simple validation - in a real app, check against stored credentials
#                 st.session_state.authenticated = True
#                 st.session_state.failed_attempts = 0
#                 st.session_state.locked_out = False
#                 st.success("Login successful!")
#                 time.sleep(1)  # Brief delay before redirect
#                 navigate_to('home')
#             else:
#                 st.error("Invalid credentials. Please try again.")

# # Main app logic
# def main():
#     # Display the appropriate page based on session state
#     if st.session_state.locked_out and not st.session_state.authenticated:
#         login_page()
#     elif st.session_state.current_page == 'home':
#         home_page()
#     elif st.session_state.current_page == 'insert':
#         insert_data_page()
#     elif st.session_state.current_page == 'retrieve':
#         retrieve_data_page()
#     elif st.session_state.current_page == 'login':
#         login_page()

# if __name__ == "__main__":
#     main()

#     # Display current stored data IDs (for demonstration purposes)
#     if st.session_state.stored_data and st.checkbox("Show stored data IDs"):
#         st.write("Currently stored data IDs:")
#         for data_id in st.session_state.stored_data:
#             st.write(f"- {data_id}")