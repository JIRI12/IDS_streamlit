import os
import pwd
import streamlit as st
import nmap
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
import netifaces
import ipaddress
from utils.database import Database

db = Database()

def get_ip_address():
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        if interface != 'lo':
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                ip_info = addresses[netifaces.AF_INET][0]
                return ip_info['addr']
    return None

def get_network_range():
    ip = get_ip_address()
    if ip:
        ip_network = ipaddress.ip_network(f'{ip}/24', strict=False)
        return str(ip_network)
    else:
        return None

def packet_callback(packet):
    if IP in packet:
        timestamp = datetime.now().timestamp()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        src_port = None
        dst_port = None
        packet_size = len(packet)
        flags = None
        payload = bytes(packet[IP].payload)
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = str(packet[TCP].flags)  # Convert flags to string
            state = "open" if packet[TCP].flags == "S" else "closed" if packet[TCP].flags == "R" else "unknown"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            state = "open"
        else:
            state = "unknown"
        
        db.store_network_data(timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size, flags, state, payload)

def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    if os.getuid() != 0:
        return

    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = pwd.getpwnam(gid_name).pw_gid

    os.setgroups([])

    os.setgid(running_gid)
    os.setuid(running_uid)

    os.umask(0o077)

def quick_scan(network_range):
    nm = nmap.PortScanner()
    results = nm.scan(hosts=network_range, arguments='-sn')  # Using -sn for a fast scan
    return results['scan']

def partial_scan(network_range):
    nm = nmap.PortScanner()
    results = nm.scan(hosts=network_range, arguments='-p 1-1024 -sT')  # Scanning only well-known ports
    return results['scan']

def semi_full_scan(network_range):
    nm = nmap.PortScanner()
    results = nm.scan(hosts=network_range, arguments='-T4 -sT')  # Using -T4 for faster scan
    return results['scan']

def full_scan(network_range):
    nm = nmap.PortScanner()
    results = nm.scan(hosts=network_range, arguments='-p- -T4 -sT')  # Full scan with all ports and faster scan
    return results['scan']

def network_scan(scan_level):
    st.header("Network Scan")
    st.write("Scanning the network...")
    
    network_range = get_network_range()
    
    if not network_range:
        st.write("Failed to determine network range.")
        return
    
    if scan_level == 'Quick Scan':
        hosts = quick_scan(network_range)
    elif scan_level == 'Partial Scan':
        hosts = partial_scan(network_range)
    elif scan_level == 'Semi-Full Scan':
        hosts = semi_full_scan(network_range)
    elif scan_level == 'Full Scan':
        hosts = full_scan(network_range)
    else:
        st.write("Invalid scan level selected.")
        return
    
    st.write("Hosts currently on the network:")
    for host in hosts:
        st.write(f"IP: {host}, Status: {hosts[host]['status']['state']}")
        for proto in hosts[host].all_protocols():
            lport = hosts[host][proto].keys()
            for port in lport:
                state = hosts[host][proto][port]['state']
                st.write(f"Storing network data: IP={host}, Protocol={proto}, Port={port}, State={state}")

    st.write("Capturing packets on the network...")
    try:
        sniff(prn=packet_callback, store=False)
    except PermissionError:
        st.write("Permission error: you need to run this script with elevated privileges.")

if __name__ == "__main__":
    if os.getuid() != 0:
        st.write("This script must be run as root to perform network scanning and packet capturing.")
    else:
        scan_level = st.selectbox('Select Scan Level', ['Quick Scan', 'Partial Scan', 'Semi-Full Scan', 'Full Scan'])
        if st.button("Start Scan"):
            network_scan(scan_level)
            drop_privileges()

"""
Sure, here's an explanation of the different scan levels implemented in your network scanning function:

### 1. Quick Scan
**Command: `nm.scan(hosts=network_range, arguments='-sn')`**

- **Purpose**: This scan is used to quickly discover live hosts on the network without probing open ports.
- **Arguments**: 
  - `-sn`: This option stands for "ping scan," which disables port scanning. Instead, it just checks which hosts are up.
- **Use Case**: Ideal for quickly identifying which devices are currently active on the network. This scan is very fast because it doesn't check for open ports or services.

### 2. Partial Scan
**Command: `nm.scan(hosts=network_range, arguments='-p 1-1024 -sT')`**

- **Purpose**: This scan is used to identify open ports on the lower, well-known range of ports (1-1024).
- **Arguments**: 
  - `-p 1-1024`: Specifies that the scan should be limited to ports 1 through 1024.
  - `-sT`: Initiates a TCP connect scan, which attempts to make a full connection to each specified port.
- **Use Case**: Useful when you need to scan common service ports quickly, such as those for web servers, FTP servers, and other commonly used services.

### 3. Semi-Full Scan
**Command: `nm.scan(hosts=network_range, arguments='-T4 -sT')`**

- **Purpose**: This scan is a faster, more aggressive scan over a larger range of ports.
- **Arguments**: 
  - `-T4`: Sets the timing template to "aggressive," which speeds up the scanning process by sending packets more frequently.
  - `-sT`: Performs a TCP connect scan.
- **Use Case**: Best for scenarios where you need more comprehensive port scanning without covering all possible ports, and you need the results faster.

### 4. Full Scan
**Command: `nm.scan(hosts=network_range, arguments='-p- -T4 -sT')`**

- **Purpose**: This scan is the most comprehensive, covering all 65,535 ports on the target hosts.
- **Arguments**: 
  - `-p-`: Instructs Nmap to scan all ports from 1 to 65535.
  - `-T4`: Uses the aggressive timing template to speed up the scan.
  - `-sT`: Performs a TCP connect scan.
- **Use Case**: Ideal when you need an exhaustive scan to find every open port on the target hosts, which is useful for thorough security assessments.

### Summary

- **Quick Scan**: Fastest, checks which hosts are up, no port scanning.
- **Partial Scan**: Scans common ports (1-1024), good balance of speed and detail.
- **Semi-Full Scan**: Faster, aggressive scan on a larger range of ports, not exhaustive.
- **Full Scan**: Most detailed, scans all possible ports, takes the longest time.

Each scan level offers a different balance between speed and comprehensiveness, allowing you to choose the appropriate one based on your specific needs and constraints.

"""