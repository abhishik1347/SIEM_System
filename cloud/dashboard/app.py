import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

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
        SELECT id, event_id, time, user, action, risk, anomaly, mitre, category
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


def _to_bool(value) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, (bytes, bytearray)):
        return any(b != 0 for b in value)

    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "t"}:
        return True
    if text in {"0", "false", "no", "n", "f", "", "none", "null"}:
        return False
    return False


def _normalize_types(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    out = df.copy()
    if "risk" in out.columns:
        out["risk"] = pd.to_numeric(out["risk"], errors="coerce").fillna(0).astype(int)
    if "anomaly" in out.columns:
        out["anomaly"] = out["anomaly"].map(_to_bool).astype(bool)
    return out


def _apply_filters(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    with st.sidebar:
        st.header("Filters")

        unique_users = ["All"] + sorted([u for u in df["user"].dropna().unique().tolist()])
        selected_user = st.selectbox("User", options=unique_users, index=0)

        event_id = st.number_input("Event ID (0 = all)", min_value=0, value=0, step=1)

        min_risk = st.slider("Min Risk", min_value=0, max_value=10, value=0)
        anomaly_only = st.checkbox("Anomaly only", value=False)

        mitres = ["All"] + sorted([m for m in df["mitre"].dropna().unique().tolist()])
        selected_mitre = st.selectbox("MITRE", options=mitres, index=0)

    filtered = df
    if selected_user != "All":
        filtered = filtered[filtered["user"] == selected_user]
    if event_id != 0:
        filtered = filtered[filtered["event_id"] == int(event_id)]
    if "risk" in filtered.columns:
        filtered = filtered[filtered["risk"].fillna(0) >= min_risk]
    if anomaly_only and "anomaly" in filtered.columns:
        filtered = filtered[filtered["anomaly"].fillna(False) == True]
    if selected_mitre != "All":
        filtered = filtered[filtered["mitre"] == selected_mitre]

    return filtered


def _style_rows(df: pd.DataFrame):
    if df.empty:
        return df

    def row_style(row):
        styles = [""] * len(row)
        try:
            risk = int(row.get("risk", 0) or 0)
        except Exception:
            risk = 0
        anomaly = bool(row.get("anomaly", False))

        # Color coding: high risk (red), anomaly (purple)
        if anomaly:
            styles = ["background-color: #6f2dbd; color: white;"] * len(row)
        elif risk >= 8:
            styles = ["background-color: #b91c1c; color: white;"] * len(row)
        return styles

    return df.style.apply(row_style, axis=1)


col_left, col_right = st.columns([1, 1])

with col_left:
    limit = st.number_input("Rows", min_value=10, max_value=2000, value=200, step=10)

with col_right:
    refresh_clicked = st.button("Refresh")

with st.expander("Auto-refresh", expanded=False):
    auto_refresh = st.checkbox("Enable auto-refresh", value=False)
    refresh_seconds = st.selectbox("Interval", options=[5, 10, 30, 60], index=2)

    # Use a lightweight HTML meta refresh to avoid extra dependencies.
    if auto_refresh:
        components.html(
            f"<meta http-equiv='refresh' content='{int(refresh_seconds)}'>",
            height=0,
        )
        st.caption(f"Auto-refreshing every {refresh_seconds} seconds.")

df = fetch_latest(int(limit))
df = _normalize_types(df)
filtered = _apply_filters(df)

if refresh_clicked:
    st.rerun()

if filtered.empty:
    st.info("No logs match the current filters.")
    st.stop()

# ================= KPIs =================
total_logs = int(len(filtered))
anomaly_count = int(filtered["anomaly"].fillna(False).sum()) if "anomaly" in filtered.columns else 0
high_risk_count = (
    int((filtered["risk"].fillna(0) >= 8).sum()) if "risk" in filtered.columns else 0
)
avg_risk = float(filtered["risk"].fillna(0).mean()) if "risk" in filtered.columns else 0.0

k1, k2, k3, k4 = st.columns(4)
k1.metric("Logs", total_logs)
k2.metric("Anomalies", anomaly_count)
k3.metric("High risk (>=8)", high_risk_count)
k4.metric("Avg risk", f"{avg_risk:.2f}")

st.subheader("Latest Logs")
display_cols = ["event_id", "time", "user", "risk", "anomaly", "mitre"]
display_cols = [c for c in display_cols if c in filtered.columns]

st.dataframe(_style_rows(filtered[display_cols]), use_container_width=True)

csv = filtered.to_csv(index=False).encode("utf-8")
st.download_button(
    label="Download CSV",
    data=csv,
    file_name="siem_logs.csv",
    mime="text/csv",
)

# ================= Row Details =================
st.subheader("Row Details")
ids = filtered["id"].tolist() if "id" in filtered.columns else list(range(len(filtered)))
selected_id = st.selectbox("Select log", options=ids, index=0)

selected_row = (
    filtered[filtered["id"] == selected_id].iloc[0].to_dict()
    if "id" in filtered.columns
    else filtered.iloc[int(selected_id)].to_dict()
)
st.json(selected_row)

st.subheader("Charts")

if "risk" in filtered.columns:
    st.caption("Risk Distribution")
    counts = filtered["risk"].value_counts().sort_index()
    st.bar_chart(counts)

if "mitre" in filtered.columns:
    st.caption("Top MITRE Techniques")
    mitre_counts = filtered["mitre"].fillna("Unknown").value_counts().head(10)
    st.bar_chart(mitre_counts)

if "time" in filtered.columns and "risk" in filtered.columns:
    st.caption("Risk Over Time")
    ts = filtered.copy()
    ts["time_parsed"] = pd.to_datetime(ts["time"], errors="coerce")
    ts = ts.dropna(subset=["time_parsed"]).sort_values("time_parsed")
    if not ts.empty:
        st.line_chart(ts.set_index("time_parsed")["risk"])
