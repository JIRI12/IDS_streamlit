import streamlit as st
from utils.auth import Auth
from utils.database import Database
import pandas as pd

# Initialize the database and authentication
db = Database()
authentication = Auth(db)

def profile():
    # Fetch current user's data from the database
    st.subheader("User Profile")
    current_user = st.session_state.username
    user = db.get_user_by_username(current_user)
    
    if user:
        # Create a DataFrame to display the current user's data
        user_data = {'Username': [user[1]], 'Role': [user[3]]}
        df = pd.DataFrame(user_data)
        
        st.table(df)
        
                
        # Password change section
        st.subheader("Change Password")
        old_password = st.text_input("Old Password", type='password')
        new_password = st.text_input("New Password", type='password')
        confirm_password = st.text_input("Confirm New Password", type='password')

        if st.button("Update Password"):
            if new_password == confirm_password:
                if authentication.login(current_user, old_password):  # Verify old password
                    hashed_password = authentication.hash_password(new_password)
                    db.update_user_password(current_user, hashed_password)
                    st.success("Password updated successfully")
                else:
                    st.error("Old password is incorrect")
            else:
                st.error("New passwords do not match")

# Call to the profile function in your main application script
if __name__ == "__main__":
    profile()
