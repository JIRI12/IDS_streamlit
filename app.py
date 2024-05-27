import streamlit as st
from nav import dashboard, login, profile
from utils.auth import Auth
from utils.database import Database
from utils.network_scan import network_scan
import pandas as pd



# Initialize the database and authentication
db = Database()
authentication = Auth(db)

# Custom CSS to style the buttons
st.markdown("""
    <style>
    [data-testid="stAppViewContainer"] {
        background-image: url("https://unsplash.com/photos/a-wooden-table-topped-with-an-hourglass-and-a-statue-AURKW6XQwawz");
        background-size: cover;
    }
    .stButton > button {
        border: none;
        width: 200px;  /* Fixed width for the buttons */
        height: 20px;
        background-color: #f0f0f0;  /* Background color to match the sidebar */
        color: #000;  /* Text color */
        padding: 5px;
        margin: 5px;
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
        confirm_password = st.text_input("Confirm Password", type='password')
        if st.button("Register"):
            if password == confirm_password:
                if authentication.register(username, password, 'admin'):
                    st.success("Admin registered successfully. Please log in.")
                    st.experimental_rerun()  # Redirect to the login page
                else:
                    st.error("Failed to register admin. Username might already exist.")
            else:
                st.error("Passwords do not match.")
        return  # Exit the main function to prevent showing the regular login/register interface

    # if 'logged_in' not in st.session_state or not st.session_state.logged_in:
    #     login()
    # else:
    #     if st.session_state.role == 'admin':
    #         manage_users()
    #     else:
    #         st.write("Welcome, you are logged in.")
    
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
                # st.session_state.page = "network_scan"
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

    # Section to add a new user
    st.subheader("Add New User")
    new_username = st.text_input("New Username", key="new_username")
    new_password = st.text_input("New Password", type='password', key="new_password")
    confirm_password = st.text_input("Confirm Password", type='password', key="confirm_password")
    role = st.selectbox("Role", ['user', 'admin'], key='new_user_role')
    if st.button("Add User"):
        if new_password == confirm_password:
            if authentication.register(new_username, new_password, role):
                st.success("User added successfully")
                st.experimental_rerun()
            else:
                st.error("Failed to add user. Username might already exist.")
        else:
            st.error("Passwords do not match.")

    # Section to edit existing users
    st.subheader("Edit Existing Users")
    
    # Fetch users from the database
    users = db.get_all_users()
    
    # Create a DataFrame to display users
    user_data = {'Username': [user[1] for user in users], 'Role': [user[3] for user in users]}
    df = pd.DataFrame(user_data)
    
    st.table(df)
    
    # Create interactive elements for each user to edit their details
    for user in users:
        with st.expander(f"Edit {user[1]}"):
            new_username = st.text_input(f"Username for {user[1]}", value=user[1], key=f"username_{user[1]}")
            new_password = st.text_input(f"New Password for {user[1]}", type='password', key=f"password_{user[1]}")
            new_role = st.selectbox(f"Role for {user[1]}", ['user', 'admin'], index=['user', 'admin'].index(user[3]), key=f"role_{user[1]}")
            
            col1, col2 = st.columns([1, 1])
            
            with col1:
                if st.button(f"Update {user[1]}", key=f"update_{user[1]}"):
                    if new_password:
                        hashed_password = authentication.hash_password(new_password)
                        db.update_user_password(user[1], hashed_password)
                    authentication.update_role(new_username, new_role)
                    st.success(f"User {user[1]} updated successfully")
                    st.experimental_rerun()
            
            with col2:
                if st.button(f"Delete {user[1]}", key=f"delete_{user[1]}"):
                    db.delete_user(user[0])
                    st.success(f"User {user[1]} deleted successfully")
                    st.rerun()

if __name__ == "__main__":
    main()

