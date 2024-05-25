import streamlit as st
from nav import dashboard, login, profile
from utils.auth import Auth
from utils.database import Database
from utils.network_scan import network_scan



# Initialize the database and authentication
db = Database()
authentication = Auth(db)

# Custom CSS to style the buttons
st.markdown("""
    <style>
    .stButton > button {
        border: none;
        width: 200px;  /* Fixed width for the buttons */
        background-color: #f0f0f0;  /* Background color to match the sidebar */
        color: #000;  /* Text color */
        padding: 10px;
        margin: 10px;
        cursor: pointer;
    }
    .stButton > button:hover {
        background-color: #e0e0e0;  /* Slightly darker background on hover */
    }
    </style>
    """, unsafe_allow_html=True)

def main():
    # Check if users table is empty
    if db.is_users_empty():
        st.title("Initial Admin Registration")
        st.write("Please register the network admin.")

        username = st.text_input("Username")
        password = st.text_input("Password", type='password')
        if st.button("Register"):
            if authentication.register(username, password, 'admin'):
                st.success("Admin registered successfully. Please log in.")
            else:
                st.error("Failed to register admin. Username might already exist.")
        return  # Exit the main function to prevent showing the regular login/register interface
    
    # Initialize session state variables
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = ''
        st.session_state.role = ''
    if 'page' not in st.session_state:
        st.session_state.page = ''

    if st.session_state.logged_in:

        st.sidebar.title(f"Hello, {st.session_state.username} ({st.session_state.role})")
        if st.sidebar.button("Dashboard", key="dashboard_button"):
            st.session_state.page = "dashboard"
        if st.sidebar.button("Profile", key="profile_button"):
            st.session_state.page = "profile"
            
        if st.session_state.role == "admin":    
            if st.sidebar.button("Network Scan", key="network_scan_button"):
                scan_level = st.selectbox('Select Scan Level', ['Quick Scan', 'Partial Scan', 'Semi-Full Scan', 'Full Scan'])
                network_scan(scan_level)
            if st.sidebar.button("Manage Users", key="manage_users_button"):
                st.session_state.page = "manage_users" 
                   
        if st.sidebar.button("Auto Simulation", key="auto_test_simulation_dropdown"):
            st.session_state.page = "automatic_simulation"
        if st.sidebar.button("Manual Simulation", key="test_simulation_dropdown"):
            st.session_state.page = "manual_simulation"
        if st.sidebar.button("Logout", key="logout_button"):
            st.session_state.page = "logout"
            st.session_state.logged_in = False
            st.session_state.username = ''
            st.rerun()

        
        st.header("Network Monitoring and Intrusion Detection")
        
        if st.session_state.page == "dashboard":
            dashboard.dashboard()
        elif st.session_state.page == "profile":
            profile.profile()
        elif st.session_state.page == "automatic_simulation":
            dashboard.auto_simulation()
        elif st.session_state.page == "network_scan":
            if st.session_state.role == "admin":
                network_scan()
        elif st.session_state.page == "manual_simulation":
            dashboard.manual_simulation()
        elif st.session_state.page == "manage_users":
            if st.session_state.role == "admin":
                manage_users()    
    else:
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Login", key="login_button"):
                st.session_state.page = "login"
                
                
        # with col2:
        #     if st.button("Register", key="register_button"):
        #         st.session_state.page = "register"

        if st.session_state.page == "login":
            login.login(authentication)
            
        # elif st.session_state.page == "register":
        #     register.register(authentication)
        
def manage_users():
    st.header("Manage Users")
    st.write("Only the admin can access this page")

    new_username = st.text_input("New Username")
    new_password = st.text_input("New Password", type='password')
    role = st.selectbox("Role", ['user', 'admin'])
    if st.button("Add User"):
        if authentication.register(new_username, new_password, role):
            st.success("User added successfully")
        else:
            st.error("Failed to add user. Username might already exist.")        


if __name__ == "__main__":
    main()

