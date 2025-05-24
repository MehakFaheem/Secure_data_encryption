import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64
import json

# Initialize session state variables
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'encryption_key' not in st.session_state:
    # Generate a key for this session (in production, this should be stored securely)
    st.session_state.encryption_key = Fernet.generate_key()

if 'is_locked' not in st.session_state:
    st.session_state.is_locked = False

# Create cipher instance
cipher = Fernet(st.session_state.encryption_key)

# Function to hash passkey using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text, passkey):
    try:
        encrypted_bytes = cipher.encrypt(text.encode())
        return base64.b64encode(encrypted_bytes).decode()
    except Exception as e:
        st.error(f"Encryption error: {str(e)}")
        return None

# Function to decrypt data
def decrypt_data(data_id, passkey):
    try:
        hashed_passkey = hash_passkey(passkey)
        
        if data_id in st.session_state.stored_data:
            stored_entry = st.session_state.stored_data[data_id]
            if stored_entry["passkey"] == hashed_passkey:
                # Reset failed attempts on successful match
                st.session_state.failed_attempts = 0
                encrypted_bytes = base64.b64decode(stored_entry["encrypted_text"].encode())
                decrypted_text = cipher.decrypt(encrypted_bytes).decode()
                return decrypted_text
        
        # Increment failed attempts
        st.session_state.failed_attempts += 1
        return None
    except Exception as e:
        st.session_state.failed_attempts += 1
        return None

# Function to reset system after successful login
def reset_failed_attempts():
    st.session_state.failed_attempts = 0
    st.session_state.is_locked = False

# Check if system should be locked
def check_lockout():
    if st.session_state.failed_attempts >= 3:
        st.session_state.is_locked = True
        return True
    return False

# Streamlit UI
st.set_page_config(page_title="Secure Data Encryption System", page_icon="🔒")
st.title("🔒 Secure Data Encryption System")

# Show current status
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Stored Entries", len(st.session_state.stored_data))
with col2:
    st.metric("Failed Attempts", st.session_state.failed_attempts)
with col3:
    if st.session_state.is_locked:
        st.error("🔒 LOCKED")
    else:
        st.success("🔓 UNLOCKED")

# Navigation
if st.session_state.is_locked:
    menu = ["Login"]
else:
    menu = ["Home", "Store Data", "Retrieve Data", "View All Data", "Login"]

choice = st.sidebar.selectbox("Navigation", menu)

# Force login page if locked
if st.session_state.is_locked and choice != "Login":
    choice = "Login"

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    
    st.markdown("### 📋 How to use:")
    st.markdown("""
    1. **Store Data**: Enter your data and create a unique passkey
    2. **Retrieve Data**: Use your data ID and passkey to decrypt your data
    3. **Security**: After 3 failed attempts, you'll need to reauthorize
    """)
    
    if st.session_state.stored_data:
        st.subheader("📊 Your Stored Data IDs:")
        for data_id in st.session_state.stored_data.keys():
            st.code(data_id)

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    
    with st.form("store_form"):
        data_id = st.text_input("Data ID (unique identifier):", help="This will be used to retrieve your data")
        user_data = st.text_area("Enter Data to Encrypt:", height=100)
        passkey = st.text_input("Enter Passkey:", type="password", help="Remember this passkey - you'll need it to decrypt!")
        confirm_passkey = st.text_input("Confirm Passkey:", type="password")
        
        submitted = st.form_submit_button("🔐 Encrypt & Save")
        
        if submitted:
            if not all([data_id, user_data, passkey, confirm_passkey]):
                st.error("⚠️ All fields are required!")
            elif passkey != confirm_passkey:
                st.error("⚠️ Passkeys don't match!")
            elif data_id in st.session_state.stored_data:
                st.error("⚠️ Data ID already exists! Choose a different ID.")
            else:
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                
                if encrypted_text:
                    st.session_state.stored_data[data_id] = {
                        "encrypted_text": encrypted_text,
                        "passkey": hashed_passkey
                    }
                    st.success("✅ Data stored securely!")
                    st.info(f"Your Data ID: **{data_id}**")
                    st.balloons()

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    if not st.session_state.stored_data:
        st.info("No data stored yet. Go to 'Store Data' to add some!")
    else:
        with st.form("retrieve_form"):
            data_id = st.selectbox("Select Data ID:", options=list(st.session_state.stored_data.keys()))
            passkey = st.text_input("Enter Passkey:", type="password")
            
            submitted = st.form_submit_button("🔓 Decrypt")
            
            if submitted:
                if not passkey:
                    st.error("⚠️ Passkey is required!")
                else:
                    decrypted_text = decrypt_data(data_id, passkey)
                    
                    if decrypted_text:
                        st.success("✅ Data decrypted successfully!")
                        st.text_area("Your Decrypted Data:", value=decrypted_text, height=100)
                        st.balloons()
                    else:
                        remaining = 3 - st.session_state.failed_attempts
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                        
                        if check_lockout():
                            st.warning("🔒 Too many failed attempts! System locked. Please login to continue.")
                            st.rerun()

elif choice == "View All Data":
    st.subheader("📋 All Stored Data")
    
    if not st.session_state.stored_data:
        st.info("No data stored yet.")
    else:
        for i, (data_id, data_info) in enumerate(st.session_state.stored_data.items(), 1):
            with st.expander(f"Entry {i}: {data_id}"):
                st.write(f"**Data ID:** {data_id}")
                st.write(f"**Encrypted Text:** {data_info['encrypted_text'][:50]}...")
                st.write(f"**Passkey Hash:** {data_info['passkey'][:20]}...")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    
    if st.session_state.failed_attempts >= 3:
        st.error(f"🔒 System locked after {st.session_state.failed_attempts} failed attempts!")
    
    st.info("Enter the master password to reset failed attempts and unlock the system.")
    
    with st.form("login_form"):
        login_pass = st.text_input("Enter Master Password:", type="password")
        submitted = st.form_submit_button("🔓 Login")
        
        if submitted:
            # In production, use a more secure authentication method
            if login_pass == "admin123":
                reset_failed_attempts()
                st.success("✅ Reauthorized successfully! System unlocked.")
                st.rerun()
            else:
                st.error("❌ Incorrect master password!")

# Sidebar information
st.sidebar.markdown("---")
st.sidebar.markdown("### 🛡️ Security Info")
st.sidebar.markdown(f"**Failed Attempts:** {st.session_state.failed_attempts}/3")
st.sidebar.markdown(f"**System Status:** {'🔒 Locked' if st.session_state.is_locked else '🔓 Unlocked'}")
st.sidebar.markdown(f"**Stored Entries:** {len(st.session_state.stored_data)}")

st.sidebar.markdown("---")
st.sidebar.markdown("### ℹ️ Instructions")
st.sidebar.markdown("""
- Store data with unique IDs and passkeys
- Use your Data ID and passkey to decrypt
- Master password: `admin123`
- System locks after 3 failed attempts
""")

# Clear all data button (for testing)
if st.sidebar.button("🗑️ Clear All Data", type="secondary"):
    st.session_state.stored_data = {}
    st.session_state.failed_attempts = 0
    st.session_state.is_locked = False
    st.sidebar.success("All data cleared!")
    st.rerun()