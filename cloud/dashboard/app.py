import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

try:
    import altair as alt
except Exception:  # pragma: no cover
    alt = None

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


def _parse_time(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty or "time" not in df.columns:
        return df
    out = df.copy()
    out["time_parsed"] = pd.to_datetime(out["time"], errors="coerce")
    return out


def _risk_band(risk: int) -> str:
    if risk >= 8:
        return "High (8-10)"
    if risk >= 4:
        return "Medium (4-7)"
    return "Low (0-3)"


def _show_risk_distribution(df: pd.DataFrame) -> None:
    st.caption("Risk Distribution")
    if "risk" not in df.columns or df.empty:
        st.info("No risk data available.")
        return

    # Build complete 0..10 distribution
    counts = df["risk"].value_counts().reindex(range(0, 11), fill_value=0).sort_index()
    dist = (
        counts.rename("count")
        .reset_index()
        .rename(columns={"index": "risk"})
    )
    total = int(dist["count"].sum()) or 1
    dist["percent"] = (dist["count"] / total * 100).round(2)
    dist["band"] = dist["risk"].apply(_risk_band)

    if alt is None:
        st.bar_chart(counts)
        st.dataframe(dist, use_container_width=True)
        return

    color_scale = alt.Scale(
        domain=["Low (0-3)", "Medium (4-7)", "High (8-10)"],
        range=["#16a34a", "#f59e0b", "#dc2626"],
    )

    bars = (
        alt.Chart(dist)
        .mark_bar()
        .encode(
            x=alt.X("risk:O", title="Risk Score (0-10)", sort=list(map(str, range(0, 11)))),
            y=alt.Y("count:Q", title="Log Count"),
            color=alt.Color("band:N", scale=color_scale, title="Band"),
            tooltip=[
                alt.Tooltip("risk:O", title="Risk"),
                alt.Tooltip("band:N", title="Band"),
                alt.Tooltip("count:Q", title="Count"),
                alt.Tooltip("percent:Q", title="Percent", format=".2f"),
            ],
        )
        .properties(height=260)
    )
    labels = (
        alt.Chart(dist)
        .mark_text(dy=-8, size=11)
        .encode(x=alt.X("risk:O", sort=list(map(str, range(0, 11)))), y="count:Q", text="count:Q")
    )
    st.altair_chart(bars + labels, use_container_width=True)


def _show_top_mitre(df: pd.DataFrame) -> None:
    st.caption("Top MITRE Techniques")
    if "mitre" not in df.columns or df.empty:
        st.info("No MITRE data available.")
        return

    tmp = df.copy()
    tmp["mitre"] = tmp["mitre"].fillna("Unknown")
    grouped = (
        tmp.groupby("mitre", dropna=False)
        .agg(
            count=("mitre", "size"),
            avg_risk=("risk", "mean") if "risk" in tmp.columns else ("mitre", "size"),
            anomalies=("anomaly", "sum") if "anomaly" in tmp.columns else ("mitre", "size"),
        )
        .reset_index()
    )

    if "risk" not in tmp.columns:
        grouped["avg_risk"] = 0.0
    if "anomaly" not in tmp.columns:
        grouped["anomalies"] = 0

    grouped["avg_risk"] = grouped["avg_risk"].fillna(0).round(2)
    grouped = grouped.sort_values(["count", "avg_risk"], ascending=False).head(15)

    if alt is None:
        st.bar_chart(grouped.set_index("mitre")["count"])
        st.dataframe(grouped, use_container_width=True)
        return

    base = alt.Chart(grouped).encode(
        y=alt.Y("mitre:N", sort="-x", title=None),
        tooltip=[
            alt.Tooltip("mitre:N", title="MITRE"),
            alt.Tooltip("count:Q", title="Count"),
            alt.Tooltip("avg_risk:Q", title="Avg Risk"),
            alt.Tooltip("anomalies:Q", title="Anomalies"),
        ],
    )

    bars = base.mark_bar().encode(
        x=alt.X("count:Q", title="Log Count"),
        color=alt.Color("avg_risk:Q", title="Avg Risk", scale=alt.Scale(scheme="yelloworangered")),
    )
    text = base.mark_text(align="left", dx=4).encode(x="count:Q", text="count:Q")
    st.altair_chart((bars + text).properties(height=380), use_container_width=True)


def _show_risk_over_time(df: pd.DataFrame) -> None:
    st.caption("Risk Over Time")
    if "time_parsed" not in df.columns or df["time_parsed"].dropna().empty:
        st.info("Time parsing failed (no valid timestamps).")
        return

    if "risk" not in df.columns:
        st.info("No risk data available.")
        return

    with st.expander("Trend settings", expanded=False):
        bucket_label = st.selectbox(
            "Time bucket",
            options=["5 min", "15 min", "1 hour", "6 hours", "1 day"],
            index=2,
            help="Controls how points are grouped for the trend chart.",
        )
        bucket_map = {
            "5 min": "5min",
            "15 min": "15min",
            "1 hour": "1h",
            "6 hours": "6h",
            "1 day": "1d",
        }
        bucket = bucket_map[bucket_label]
        show_data = st.checkbox("Show aggregated trend table", value=False)

    ts = df.dropna(subset=["time_parsed"]).copy()
    ts = ts.sort_values("time_parsed")
    ts["bucket"] = ts["time_parsed"].dt.floor(bucket)

    agg = (
        ts.groupby("bucket")
        .agg(
            logs=("risk", "size"),
            avg_risk=("risk", "mean"),
            max_risk=("risk", "max"),
            anomalies=("anomaly", "sum") if "anomaly" in ts.columns else ("risk", "size"),
        )
        .reset_index()
    )
    if "anomaly" not in ts.columns:
        agg["anomalies"] = 0
    agg["avg_risk"] = agg["avg_risk"].round(2)

    if show_data:
        st.dataframe(agg, use_container_width=True)

    if alt is None:
        st.line_chart(agg.set_index("bucket")["avg_risk"])
        return

    base = alt.Chart(agg).encode(
        x=alt.X("bucket:T", title="Time"),
        tooltip=[
            alt.Tooltip("bucket:T", title="Time"),
            alt.Tooltip("logs:Q", title="Logs"),
            alt.Tooltip("avg_risk:Q", title="Avg Risk"),
            alt.Tooltip("max_risk:Q", title="Max Risk"),
            alt.Tooltip("anomalies:Q", title="Anomalies"),
        ],
    )

    logs_bar = base.mark_bar(opacity=0.25, color="#2563eb").encode(
        y=alt.Y("logs:Q", title="Log Volume")
    ).properties(height=220)

    risk_line = base.mark_line(point=True, color="#dc2626").encode(
        y=alt.Y("avg_risk:Q", title="Average Risk", scale=alt.Scale(domain=[0, 10]))
    ).properties(height=220)

    max_line = base.mark_line(strokeDash=[4, 4], color="#7c2d12").encode(
        y=alt.Y("max_risk:Q", title="Average / Max Risk", scale=alt.Scale(domain=[0, 10]))
    ).properties(height=220)

    anomaly_pts = base.mark_point(filled=True, size=60, color="#6f2dbd").encode(
        y=alt.Y("anomalies:Q", title="Anomalies")
    ).properties(height=220)

    st.altair_chart(alt.layer(logs_bar, risk_line, max_line).resolve_scale(y="independent"), use_container_width=True)
    if "anomaly" in ts.columns:
        st.altair_chart(
            base.mark_bar(color="#6f2dbd").encode(y=alt.Y("anomalies:Q", title="Anomaly Count")).properties(height=180),
            use_container_width=True,
        )


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
df = _parse_time(df)
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

_show_risk_distribution(filtered)
_show_top_mitre(filtered)
_show_risk_over_time(filtered)
