from __future__ import annotations

from typing import Any, Dict, List

from backend.aggregator.risk_aggregator import aggregate_by_user
from backend.anomaly.anomaly_engine import detect_anomaly
from backend.database.db_manager import get_connection, insert_log
from backend.normalizer.mitre_mapper import map_to_mitre
from backend.scorer.risk_engine import calculate_risk


UNKNOWN_USER = "UNKNOWN_USER"


def _normalize_event_id(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except Exception:
        return None


def _normalize_time(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def ensure_logs_table() -> None:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            event_id INT,
            time VARCHAR(64),
            user VARCHAR(255) NOT NULL,
            action VARCHAR(255),
            risk INT,
            category VARCHAR(255),
            mitre VARCHAR(255),
            anomaly BOOLEAN,
            UNIQUE KEY uniq_event_time_user (event_id, time, user)
        )
        """
    )
    conn.commit()
    cursor.close()
    conn.close()


def _normalize_user(value: Any) -> str:
    if value is None:
        return UNKNOWN_USER
    text = str(value).strip()
    if not text or text.lower() == "none":
        return UNKNOWN_USER
    return text


def process_and_store_logs(logs: List[Dict[str, Any]]) -> int:
    if not logs:
        return 0

    enriched: List[Dict[str, Any]] = []

    # 1) Per-log enrichment (risk + MITRE)
    for raw in logs:
        if not isinstance(raw, dict):
            continue

        event = dict(raw)

        event_id = _normalize_event_id(event.get("event_id"))
        event_time = _normalize_time(event.get("time"))
        if event_id is None or event_time is None:
            continue

        event["event_id"] = event_id
        event["time"] = event_time

        event["user"] = _normalize_user(event.get("user"))
        event["action"] = event.get("action") or "other"

        ocsf = event.get("ocsf")
        if not isinstance(ocsf, dict):
            ocsf = {"category": "unknown"}
        if "category" not in ocsf:
            ocsf["category"] = "unknown"
        event["ocsf"] = ocsf

        event["risk"] = calculate_risk(event)
        event["mitre"] = map_to_mitre(event_id)

        enriched.append(event)

    # 2) Aggregate user risk (batch total)
    totals = aggregate_by_user(enriched)

    # 3) Detect anomaly and store
    for event in enriched:
        user = event["user"]
        total_risk = totals.get(user, 0)
        anomaly_flag, _z, _confidence = detect_anomaly(user, total_risk)
        event["anomaly"] = bool(anomaly_flag)

        insert_log(event)

    return len(enriched)
