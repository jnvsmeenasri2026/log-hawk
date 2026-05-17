import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from analyzer import parse_logs, detect_threats, get_summary

# Page config
st.set_page_config(
    page_title="Log Hawk",
    page_icon="🦅",
    layout="centered"
)

# Title
st.title("🦅 Log Hawk")
st.markdown("*Watches your logs like a hawk!*")
st.markdown("---")

# File upload section
st.subheader("📂 Upload Log File")
uploaded_file = st.file_uploader("Choose a log file", 
                                  type=["log", "txt"])

# Also allow sample log
use_sample = st.checkbox("Use sample.log for testing")

st.markdown("---")

if uploaded_file or use_sample:

    # Read file content
    if use_sample:
        with open("sample.log", "r") as f:
            content = f.read()
    else:
        content = uploaded_file.read().decode("utf-8")

    # Parse logs
    df = parse_logs(content)

    if df.empty:
        st.error("❌ No valid logs found in file!")
    else:
        # Summary section
        summary = get_summary(df)
        st.subheader("📊 Log Summary")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Logs", summary["total"])
        col2.metric("✅ Info", summary["info"])
        col3.metric("⚠️ Warnings", summary["warning"])
        col4.metric("🔴 Errors", summary["error"])

        st.markdown("---")

        # Threat Detection
        st.subheader("🚨 Threat Analysis")
        threats = detect_threats(df)

        if threats:
            for threat in threats:
                if threat["severity"] == "HIGH":
                    st.error(f"{threat['type']} — {threat['detail']}")
                elif threat["severity"] == "MEDIUM":
                    st.warning(f"{threat['type']} — {threat['detail']}")
                else:
                    st.info(f"{threat['type']} — {threat['detail']}")
        else:
            st.success("✅ No threats detected! Logs look clean!")

        st.markdown("---")

        # Chart section
        st.subheader("📈 Log Activity Chart")

        # Count by level
        level_counts = df['level'].value_counts()

        fig, ax = plt.subplots()
        colors = []
        for level in level_counts.index:
            if level == 'INFO':
                colors.append('green')
            elif level == 'WARNING':
                colors.append('orange')
            else:
                colors.append('red')

        ax.bar(level_counts.index, 
               level_counts.values, 
               color=colors)
        ax.set_title("Log Events by Type")
        ax.set_xlabel("Log Level")
        ax.set_ylabel("Count")
        st.pyplot(fig)

        st.markdown("---")

        # Raw logs table
        st.subheader("📋 Raw Log Data")
        st.dataframe(df[["date", "time", 
                         "level", "message"]], 
                    use_container_width=True)

# Footer
st.markdown("---")
st.caption("🦅 Log Hawk — Cybersecurity Log Analyzer")