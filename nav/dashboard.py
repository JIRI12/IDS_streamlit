import streamlit as st
import pandas as pd
import random
import joblib
from streamlit_autorefresh import st_autorefresh
import numpy as np
import matplotlib.pyplot as plt

# Load the models
try:
    model = joblib.load('/home/kudakwashe/IDS_streamlite/models/randomForest/model.pkl')
    nslkdd_model = joblib.load('/home/kudakwashe/IDS_streamlite/models/randomForest/nslkdd_model.pkl')
except Exception as e:
    st.error(f"Failed to load models: {e}")

# Load the data
try:
    data = pd.read_csv("/home/kudakwashe/IDS_streamlite/datasets/pockects.txt", sep='\t')
    data2 = pd.read_csv("/home/kudakwashe/IDS_streamlite/datasets/unsw_packects_updated.csv", sep=';')
except Exception as e:
    st.error(f"Failed to load datasets: {e}")

def model1(input_data):
    # Preprocess the input data in the same way you did during training
    model_estimate = model.predict([input_data])[0]
    return model_estimate

def model2(input_data):
    # Preprocess the input data in the same way you did during training
    model2_estimate = nslkdd_model.predict([input_data])[0]
    return model2_estimate

def classify_with_model1():
    datat2 = data2.iloc[random.randint(0, len(data2) - 1)]
    packet = list(datat2)
    table1 = {
        'Field': data2.columns,
        'Network Packet': packet,
    }
    df1 = pd.DataFrame(table1)
    t1 = df1.T   
    st.dataframe(df1, use_container_width=True)
    classification = model1(packet)
    if classification == 0:
        st.write("Classification: Normal")
    else:
        st.write("Classification: Intrusion Detected")

def classify_with_model2():
    datat = data.iloc[random.randint(0, len(data) - 1)]
    pocket = list(datat)
    table = {
        'Field': ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "level"],
        'Network Packet': pocket,
    }
    df = pd.DataFrame(table)
    t = df.T
    st.dataframe(df, use_container_width=True)
    classification2 = model2(pocket)
    if classification2 == 0:
        st.write("Classification: Normal")
    else:
        st.write("Classification: Intrusion Detected")

def dashboard():
    st.markdown(f"<h5 style='text-align:center;'>Random Forest vs Q-Learning Performance Metrics</h5>", unsafe_allow_html=True)

    # Assuming you have the following performance metrics
    accuracy_score = 0.9521692060639302
    f1_score = 0.9592630953907155
    recall_score = 0.9893459727410929

    Q_accuracy_score = 0.9821692060639302
    Q_f1_score = 0.9292630953907155
    Q_recall_score = 0.893459727410929

    # Create the bar chart
    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(3)
    width = 0.4

    ax.bar(x - width/2, [accuracy_score, f1_score, recall_score], width, label='Random Forest Regressor')
    ax.bar(x + width/2, [Q_accuracy_score, Q_f1_score, Q_recall_score], width, label='Q-Learning')

    ax.set_xticks(x)
    ax.set_xticklabels(['Accuracy', 'F1 Score', 'Recall'])
    ax.set_ylabel('Score')
    ax.set_title('Performance Metrics Comparison')
    ax.legend()

    st.pyplot(fig)

    # Create the comparison table
    data = {
        'Metric': ['Accuracy', 'F1 Score', 'Recall'],
        'Random Forest Regressor': [accuracy_score, f1_score, recall_score],
        'Q-Learning': [Q_accuracy_score, Q_f1_score, Q_recall_score]
    }

    df = pd.DataFrame(data)
    st.table(df)


def login():
    # page = st.sidebar.selectbox('Select Model:', ["Dashboard", "Random Forest"])

    # if page == 'Dashboard':
    st.subheader("Dashboard")
    st.write("Random Forest Regressor")
    st.write("Q-login")

def auto_simulation():
    st.subheader("Random Forest")
    count = st_autorefresh(interval=7*1000, limit=100, key="random_forest_autorefresh")

    col1, col2 = st.columns(2)
    with col1:
        st.write("Trained with UNSW-NB15 dataset")
        classify_with_model1()
    with col2:
        st.write("Trained with NSL-KDD dataset")   
        classify_with_model2()


    st.subheader("Q-Learning")
    st.write("Q-Learning Detailed Performance")


def manual_classification(pocket):
    manual_classification = model2(pocket)
    if manual_classification == 0:
        st.write("Classification: Normal")
    else:
        st.write("Classification: Intrusion Detected")

def manual_simulation():
    # List to store inputted numbers
    pocket1 = []

    # List of all values
    values = [
        ("duration", 232.799201), ("protocol_type", 1.080985), ("service", 34.591746), 
        ("flag", 6.853117), ("src_bytes", 20276.850233), ("dst_bytes", 2388.785889), 
        ("land", 0.000444), ("wrong_fragment", 0.007766), ("urgent", 0.001109), 
        ("hot", 0.124251), ("num_failed_logins", 0.024850), ("logged_in", 0.439982), 
        ("num_compromised", 0.082538), ("root_shell", 0.001997), ("su_attempted", 0.000000), 
        ("num_root", 0.068116), ("num_file_creations", 0.030175), ("num_shells", 0.001997), 
        ("num_access_files", 0.003994), ("num_outbound_cmds", 0.000000), ("is_host_login", 0.000000), 
        ("is_guest_login", 0.028400), ("count", 79.679166), ("srv_count", 29.855558), 
        ("serror_rate", 0.101047), ("srv_serror_rate", 0.101023), ("rerror_rate", 0.241140), 
        ("srv_rerror_rate", 0.237599), ("same_srv_rate", 0.735866), ("diff_srv_rate", 0.096390), 
        ("srv_diff_host_rate", 0.103521), ("dst_host_count", 192.919459), ("dst_host_srv_count", 139.191480), 
        ("dst_host_same_srv_rate", 0.606838), ("dst_host_diff_srv_rate", 0.093122), 
        ("dst_host_same_src_port_rate", 0.128880), ("dst_host_srv_diff_host_rate", 0.018329), 
        ("dst_host_serror_rate", 0.097127), ("dst_host_srv_serror_rate", 0.098664), 
        ("dst_host_rerror_rate", 0.233057), ("dst_host_srv_rerror_rate", 0.227619), 
        ("level", 17.994231)
    ]

    num_rows = (len(values) + 2) // 3

    # Iterate through the rows and display values in columns
    for i in range(num_rows):
        cols = st.columns(3)
        for j in range(3):
            idx = i * 3 + j
            if idx < len(values):
                col_name, col_value = values[idx]
                with cols[j]:
                    # Store the inputted number in the list
                    inputted_number = st.number_input(col_name, value=col_value, key=f"{col_name}_input")
                    pocket1.append(inputted_number)
            else:
                break

    # Button to trigger classification
    if st.button("Classify"):
        manual_classification(pocket1)


if __name__ == "__main__":
    dashboard()
