import streamlit as st
from utils.auth import Auth
from utils.database import Database
import pandas as pd

# Initialize the database and authentication
db = Database()
authentication = Auth(db)

def profile():
    st.header(st.session_state.username)
    #st.write("Profile page content goes here.")

    if st.session_state.role == "admin":
        st.subheader("User Management")
        
        # Fetch users from the database
        users = db.get_all_users()
        
        # Create a DataFrame to display users
        user_data = {'Username': [user[1] for user in users], 'Role': [user[3] for user in users]}
        df = pd.DataFrame(user_data)
        
        st.table(df)

        # Create interactive elements for each user
        for user in users:
            new_role = st.selectbox(f"Change role for {user[1]}", ['user', 'admin'], index=['user', 'admin'].index(user[3]))
            if st.button(f"Update Role for {user[1]}"):
                authentication.update_role(user[1], new_role)
                st.success(f"Role updated for {user[1]}")
                st.rerun()
                
# call to the profile function in your main application script
if __name__ == "__main__":
    profile()                