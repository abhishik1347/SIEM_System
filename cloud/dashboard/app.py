import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# Allow running via: `streamlit run cloud/dashboard/app.py`
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.database.db_manager import get_connection


st.set_page_config(page_title="Cloud SIEM Dashboard", layout="wide")
st.title("Cloud SIEM Dashboard")


def fetch_latest(limit: int = 200) -> pd.DataFrame:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT event_id, time, user, risk, anomaly, mitre
        FROM logs
        ORDER BY id DESC
        LIMIT %s
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return pd.DataFrame(rows)


limit = st.number_input("Rows", min_value=10, max_value=2000, value=200, step=10)
df = fetch_latest(int(limit))

st.subheader("Latest Logs")
st.dataframe(df, use_container_width=True)

if not df.empty and "risk" in df.columns:
    st.subheader("Risk Distribution")
    counts = df["risk"].value_counts().sort_index()
    st.bar_chart(counts)
