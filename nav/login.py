import streamlit as st

def login(auth):
    st.title("Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type='password')
    if st.button("SUBMIT"):
        if auth.login(username, password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success("Logged in successfully")
            st.rerun()
        else:
            st.error("Invalid username or password")
