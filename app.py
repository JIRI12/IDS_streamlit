import streamlit as st
from pages import dashboard, login, register, profile
from utils.auth import Auth
from utils.database import Database
import nmap

# Initialize the database and authentication
db = Database()
authentication = Auth(db)

def main():
    st.title("Network Monitoring and Intrusion Detection Dashboard")

    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = ''

    if st.session_state.logged_in:
        st.sidebar.title(f"Welcome, {st.session_state.username}")
        page = st.sidebar.selectbox("Select Page", ["Dashboard", "Profile", "Logout", "Network Scan"])
        
        if page == "Dashboard":
            dashboard.dashboard()
        elif page == "Profile":
            profile.profile()
        elif page == "Network Scan":
            network_scan()
        elif page == "Logout":
            st.session_state.logged_in = False
            st.session_state.username = ''
            st.experimental_rerun()
    else:
        page = st.sidebar.selectbox("Select Page", ["Login", "Register"])
        
        if page == "Login":
            login.login(authentication)
        elif page == "Register":
            register.register(authentication)

def network_scan():
    st.header("Network Scan")
    st.write("Scanning the network...")

    nm = nmap.PortScanner()

    @st.cache_data(ttl=60)
    def scan_network():
        results = nm.scan(hosts='192.168.0.1/24', arguments='-sT')
        return results['scan']

    hosts = scan_network()
    st.write("Hosts currently on the network:")
    for host in hosts:
        st.write(f"IP: {host}, Status: {hosts[host]['status']['state']}")
        
        for proto in hosts[host].all_protocols():
            lport = hosts[host][proto].keys()
            for port in lport:
                state = hosts[host][proto][port]['state']
                st.write(f"Storing data: IP={host}, Protocol={proto}, Port={port}, State={state}")
                db.store_network_data(host, proto, port, state)

if __name__ == "__main__":
    main()
