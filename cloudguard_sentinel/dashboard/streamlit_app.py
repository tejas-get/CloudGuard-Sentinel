import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database.db')

st.set_page_config(
    page_title="CloudGuard Sentinel — Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark theme CSS
st.markdown("""
<style>
    .main { background-color: #020b14; }
    .stMetric { background: #061524; border: 1px solid #0d3352; border-radius: 8px; padding: 16px; }
    .metric-high { color: #ff3c5a !important; }
    .metric-low { color: #00ff9d !important; }
    h1, h2, h3 { color: #c8e6f5; font-family: 'Rajdhani', sans-serif; }
</style>
""", unsafe_allow_html=True)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@st.cache_data(ttl=10)
def load_data():
    conn = get_db()
    logs = pd.read_sql_query("SELECT * FROM access_logs ORDER BY id DESC LIMIT 500", conn)
    anomalies = pd.read_sql_query("SELECT * FROM anomaly_scores ORDER BY id DESC LIMIT 500", conn)
    alerts = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 100", conn)
    users = pd.read_sql_query("SELECT id, username, role, is_suspicious, created_at FROM users", conn)
    conn.close()
    return logs, anomalies, alerts, users

st.sidebar.markdown("## 🛡️ CloudGuard Sentinel")
st.sidebar.markdown("**Research Analytics Dashboard**")
st.sidebar.markdown("---")
st.sidebar.markdown("*Context-Aware Cloud Access Behavior Monitoring and Hybrid Anomaly Detection*")
st.sidebar.markdown("---")

page = st.sidebar.radio("Navigation", [
    "📊 Overview",
    "🔍 Anomaly Analysis",
    "⚠️ Alerts",
    "👥 Users",
    "📋 Raw Logs",
])

st.sidebar.markdown("---")
if st.sidebar.button("🔄 Refresh Data"):
    st.cache_data.clear()
    st.rerun()

logs, anomalies, alerts, users = load_data()

if page == "📊 Overview":
    st.title("🛡️ CloudGuard Sentinel — Threat Intelligence Overview")
    st.markdown("*Real-time cloud access behavior monitoring using Hybrid ML anomaly detection*")

    col1, col2, col3, col4 = st.columns(4)
    risk_counts = anomalies['risk_level'].value_counts() if not anomalies.empty else {}

    with col1:
        st.metric("Total Access Events", len(logs), delta=None)
    with col2:
        st.metric("🔴 High Risk", int(risk_counts.get('HIGH', 0)))
    with col3:
        st.metric("🟡 Medium Risk", int(risk_counts.get('MEDIUM', 0)))
    with col4:
        st.metric("⚠️ Active Alerts", len(alerts[alerts['acknowledged'] == 0]) if not alerts.empty else 0)

    st.markdown("---")
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Risk Distribution")
        if not anomalies.empty:
            rc = anomalies['risk_level'].value_counts().reset_index()
            rc.columns = ['Risk Level', 'Count']
            colors = {'HIGH': '#ff3c5a', 'MEDIUM': '#ffaa00', 'LOW': '#00ff9d'}
            fig = px.pie(rc, values='Count', names='Risk Level',
                        color='Risk Level', color_discrete_map=colors,
                        hole=0.4)
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                            font_color='#c8e6f5', height=300)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No anomaly data yet.")

    with col2:
        st.subheader("Access Timeline (Hourly)")
        if not logs.empty and 'hour_of_day' in logs.columns:
            hourly = logs.groupby('hour_of_day').size().reset_index(name='count')
            fig = px.bar(hourly, x='hour_of_day', y='count',
                        color_discrete_sequence=['#00c2ff'])
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                            font_color='#c8e6f5', height=300, xaxis_title='Hour', yaxis_title='Events')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No log data yet.")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Device Type Breakdown")
        if not logs.empty and 'device_type' in logs.columns:
            dc = logs['device_type'].value_counts().reset_index()
            dc.columns = ['Device', 'Count']
            fig = px.bar(dc, x='Device', y='Count', color='Device',
                        color_discrete_sequence=['#00c2ff', '#00ff9d', '#ffaa00', '#ff3c5a'])
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                            font_color='#c8e6f5', height=260, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Isolation Score Distribution")
        if not anomalies.empty and 'isolation_score' in anomalies.columns:
            fig = px.histogram(anomalies, x='isolation_score', nbins=20,
                            color_discrete_sequence=['#00ff9d'])
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                            font_color='#c8e6f5', height=260, xaxis_title='Score', yaxis_title='Count')
            st.plotly_chart(fig, use_container_width=True)

elif page == "🔍 Anomaly Analysis":
    st.title("🔍 Hybrid Anomaly Detection Results")
    st.markdown("*Isolation Forest (unsupervised ML) + Rule-Based Validation*")

    if anomalies.empty:
        st.info("No anomaly data available yet. Log in as different users to generate data.")
    else:
        col1, col2, col3 = st.columns(3)
        with col1:
            filter_risk = st.multiselect("Filter by Risk Level", ['HIGH', 'MEDIUM', 'LOW'],
                                        default=['HIGH', 'MEDIUM', 'LOW'])
        with col2:
            filter_user = st.multiselect("Filter by User", anomalies['username'].unique().tolist(),
                                        default=anomalies['username'].unique().tolist())
        with col3:
            st.metric("Filtered Records", len(anomalies[
                anomalies['risk_level'].isin(filter_risk) & anomalies['username'].isin(filter_user)
            ]))

        filtered = anomalies[
            anomalies['risk_level'].isin(filter_risk) & anomalies['username'].isin(filter_user)
        ]

        st.subheader("Anomaly Score Timeline")
        if not filtered.empty and 'isolation_score' in filtered.columns:
            fig = px.scatter(filtered, x=filtered.index, y='isolation_score',
                           color='risk_level',
                           color_discrete_map={'HIGH': '#ff3c5a', 'MEDIUM': '#ffaa00', 'LOW': '#00ff9d'},
                           hover_data=['username', 'rule_flags'])
            fig.add_hline(y=0.5, line_dash="dash", line_color="#4a7a9b", annotation_text="Threshold")
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                            font_color='#c8e6f5', height=350)
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Detection Results Table")
        display_cols = ['id', 'username', 'timestamp', 'isolation_score', 'risk_level', 'rule_flags']
        available = [c for c in display_cols if c in filtered.columns]
        st.dataframe(
            filtered[available].style.applymap(
                lambda v: 'background-color: rgba(255,60,90,0.2)' if v == 'HIGH'
                else ('background-color: rgba(255,170,0,0.15)' if v == 'MEDIUM' else ''),
                subset=['risk_level'] if 'risk_level' in filtered.columns else []
            ),
            use_container_width=True, height=400
        )

elif page == "⚠️ Alerts":
    st.title("⚠️ Security Alerts")
    if alerts.empty:
        st.success("✅ No alerts triggered. System is clean.")
    else:
        open_alerts = alerts[alerts['acknowledged'] == 0]
        acked_alerts = alerts[alerts['acknowledged'] == 1]

        col1, col2 = st.columns(2)
        with col1:
            st.metric("🔴 Open Alerts", len(open_alerts))
        with col2:
            st.metric("✅ Acknowledged", len(acked_alerts))

        if not open_alerts.empty:
            st.subheader("🔴 Open Alerts")
            for _, row in open_alerts.iterrows():
                with st.expander(f"⚠️ [{row['risk_level']}] {row['username']} — {str(row['timestamp'])[:19]}"):
                    st.markdown(f"**Message:** {row['message']}")
                    st.markdown(f"**Timestamp:** {row['timestamp']}")

        if not acked_alerts.empty:
            st.subheader("✅ Acknowledged Alerts")
            st.dataframe(acked_alerts, use_container_width=True)

elif page == "👥 Users":
    st.title("👥 User Management")
    if users.empty:
        st.info("No users found.")
    else:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Users", len(users))
        with col2:
            st.metric("Admins", len(users[users['role'] == 'admin']))
        with col3:
            st.metric("🚨 Suspicious", len(users[users['is_suspicious'] == 1]))

        def highlight_suspicious(row):
            if row.get('is_suspicious') == 1:
                return ['background-color: rgba(255,60,90,0.15)'] * len(row)
            return [''] * len(row)

        st.dataframe(users.style.apply(highlight_suspicious, axis=1), use_container_width=True)

elif page == "📋 Raw Logs":
    st.title("📋 Raw Access Logs")
    if logs.empty:
        st.info("No log data yet.")
    else:
        st.markdown(f"**{len(logs)} records loaded** (latest 500)")
        search = st.text_input("🔍 Filter by username")
        if search:
            display_logs = logs[logs['username'].str.contains(search, case=False, na=False)]
        else:
            display_logs = logs
        st.dataframe(display_logs, use_container_width=True, height=500)

st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#4a7a9b;font-size:0.75rem;font-family:monospace;'>"
    "CloudGuard Sentinel · Context-Aware Cloud Access Behavior Monitoring · "
    "Hybrid ML Anomaly Detection System · Research Implementation"
    "</div>",
    unsafe_allow_html=True
)
