import streamlit as st

def profile():
    st.header(st.session_state.username)
    st.write("Profile page content goes here.")
