import streamlit as st
import pandas as pd
import time
import os

LOG_FILE = "ids_log.csv"

st.set_page_config(page_title="Network IDS Dashboard", layout="wide")

st.title("🚨 Real-Time Network Intrusion Detection System")

table_placeholder = st.empty()
stats_placeholder = st.empty()

while True:

    if os.path.exists(LOG_FILE):

        df = pd.read_csv(LOG_FILE)

        if not df.empty:

            # ----- Statistics -----

            total_events = len(df)

            dos_attacks = len(df[df["status"] == "DOS ATTACK"])

            suspicious = len(df[df["status"] == "SUSPICIOUS"])

            top_ip = df["src_ip"].value_counts().idxmax()

            stats_placeholder.markdown(
                f"""
                ### 📊 Traffic Statistics

                **Total Events:** {total_events}  
                **Suspicious Traffic:** {suspicious}  
                **DoS Attacks:** {dos_attacks}  
                **Top Source IP:** {top_ip}
                """
            )

            # ----- Alerts -----

            latest_event = df.iloc[-1]

            if latest_event["risk"] == "HIGH":

                st.error(
                    f"⚠ DOS ATTACK DETECTED from {latest_event['src_ip']}"
                )

            elif latest_event["risk"] == "MEDIUM":

                st.warning(
                    f"⚠ Suspicious traffic from {latest_event['src_ip']}"
                )

            # ----- Table -----

            table_placeholder.dataframe(df.tail(20), use_container_width=True)

    time.sleep(2)