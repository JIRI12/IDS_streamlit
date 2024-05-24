import plotly.express as px
import pandas as pd

def visualize_network_data(network_data):
    df = pd.DataFrame(network_data, columns=["ID", "Timestamp", "Packet Loss", "Latency", "Bandwidth Usage"])
    fig = px.line(df, x="Timestamp", y=["Packet Loss", "Latency", "Bandwidth Usage"], title="Network Data Over Time")
    return fig

def visualize_performance_metrics(performance_metrics):
    df = pd.DataFrame(performance_metrics)
    fig = px
