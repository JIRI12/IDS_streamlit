import streamlit as st

def register(auth):
    st.title("Register")

    username = st.text_input("Username")
    password = st.text_input("Password", type='password')
    if st.button("Register"):
        if auth.register(username, password):
            st.success("Registered successfully")
            st.session_state.logged_in = True
            st.session_state.username = username
            st.rerun()
        else:
            st.error("Username already exists")
