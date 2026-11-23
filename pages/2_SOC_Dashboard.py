import streamlit as st

from src.dashboard import render_dashboard

st.set_page_config(
    page_title="PhishGuard SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
)

render_dashboard()

