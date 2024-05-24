import streamlit as st
import pandas as pd
import random
import joblib

# Load the models
try:
    model = joblib.load('/home/kudakwashe/IDS_streamlite/models/randomForest/model.pkl')
    nslkdd_model = joblib.load('/home/kudakwashe/IDS_streamlite/models/randomForest/nslkdd_model.pkl')
except Exception as e:
    st.error(f"Failed to load models: {e}")

# Load the data
try:
    data = pd.read_csv("/home/kudakwashe/IDS_streamlite/datasets/nslkdd_packects.csv", sep='\t')
    data2 = pd.read_csv("/home/kudakwashe/IDS_streamlite/datasets/unsw_packects_updated.csv", sep=';')
except Exception as e:
    st.error(f"Failed to load datasets: {e}")

# Functions for the models
def model1(*args):
    input_data = [args]
    try:
        return model.predict(input_data)[0]
    except Exception as e:
        st.error(f"Failed to predict using model1: {e}")
        return None

def model2(*args):
    input_data = [args]
    try:
        return nslkdd_model.predict(input_data)[0]
    except Exception as e:
        st.error(f"Failed to predict using model2: {e}")
        return None

def dashboard():
    st.header("Dashboard")
    page = st.sidebar.selectbox('Select Model:', ["Dashboard", "Random Forest", "Q-Learning"])

    if page == 'Dashboard':
        st.write("Random Forest Regressor")
        st.write("Q-Learning")

    elif page == "Random Forest":
        st.write("Trained with UNSWNB15 dataset")
        if st.button("Classify UNSWNB15"):
            datat2 = data2.iloc[random.randint(0, len(data2)-1)]
            packet = list(datat2)
            table1 = {
                'Field': ["dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "inpkt", "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean", "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports"],
                'Value': packet,
            }

            # Debugging output
            st.write(f"Length of 'Field': {len(table1['Field'])}")
            st.write(f"Length of 'Value': {len(table1['Value'])}")
            
            # Ensure both lists have the same length
            if len(table1['Field']) == len(table1['Value']):
                df1 = pd.DataFrame(table1)
                classification = model1(*packet)
                st.dataframe(df1)
                if classification is not None:
                    st.write("Classification: Normal" if classification == 0 else "Classification: Intrusion Detected")
            else:
                st.error("Field and Value lists are not of the same length. Please check the data.")

        st.write("Trained with NSLKDD dataset")
        if st.button("Classify NSLKDD"):
            datat = data.iloc[random.randint(0, len(data)-1)]
            pocket = list(datat)
            table = {
                'Field': ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "level"],
                'Value': pocket,
            }

            # Debugging output
            st.write(f"Length of 'Field': {len(table['Field'])}")
            st.write(f"Length of 'Value': {len(table['Value'])}")

            # Ensure both lists have the same length
            if len(table['Field']) == len(table['Value']):
                df = pd.DataFrame(table)
                classification2 = model2(*pocket)
                st.dataframe(df)
                if classification2 is not None:
                    st.write("Classification: Normal" if classification2 == 0 else "Classification: Intrusion Detected")
            else:
                st.error("Field and Value lists are not of the same length. Please check the data.")

    elif page == "Q-Learning":
        st.write("Q-Learning Detailed Performance")

