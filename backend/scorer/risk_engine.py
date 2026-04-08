from collections import defaultdict
from datetime import datetime

failed_login_counter = defaultdict(int)
recent_suspicious_launcher = defaultdict(lambda: None)
remote_logon_counter = defaultdict(int)

# Suspicious binaries often used by attackers
SUSPICIOUS_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "wmic.exe",
    "rundll32.exe",
    "mshta.exe",
    "cscript.exe",
    "wscript.exe",
    "regsvr32.exe",
    "mimikatz.exe"
]

SEVERITY_MAP = {
    4624: 2,
    4625: 6,
    4672: 7,
    4720: 8,
    4728: 9,
    4732: 9,
    4756: 9,
    4697: 8,
    1102: 10,
    4688: 4
}


LATERAL_LOGON_TYPES = {"3", "10"}  # network / remote interactive (RDP)


def _is_suspicious_process(process_name):
    if not process_name:
        return False
    lowered = str(process_name).lower()

    if any(proc in lowered for proc in SUSPICIOUS_PROCESSES):
        return True

    suspicious_patterns = [
        "-enc ",
        " encodedcommand",
        " iwr ",
        " invoke-webrequest",
        " downloadstring",
        " frombase64string",
    ]
    return any(pattern in lowered for pattern in suspicious_patterns)


def _parse_iso_time(value):
    if not value:
        return None
    try:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _apply_process_chain_heuristic(event, base_score):
    if event.get("event_id") != 4688:
        return base_score

    user = str(event.get("user") or "unknown")
    process_name = event.get("process_name")
    now = _parse_iso_time(event.get("time"))

    if _is_suspicious_process(process_name):
        previous = recent_suspicious_launcher.get(user)
        if previous and previous.get("time") and now:
            delta_seconds = (now - previous["time"]).total_seconds()
            if 0 <= delta_seconds <= 120:
                base_score += 2

        recent_suspicious_launcher[user] = {
            "time": now,
            "process": str(process_name).lower(),
        }

    return base_score


def _apply_lateral_movement_heuristic(event, base_score):
    if event.get("event_id") != 4624:
        return base_score

    logon_type = str(event.get("logon_type") or "").strip()
    user = str(event.get("user") or "unknown")

    if logon_type in LATERAL_LOGON_TYPES:
        remote_logon_counter[user] += 1
        base_score += 2

        if remote_logon_counter[user] >= 3:
            base_score += 2

    return base_score

def calculate_risk(event):

    event_id = event["event_id"]
    base_score = SEVERITY_MAP.get(event_id, 1)

    # ========== Brute Force Escalation ==========
    if event_id == 4625:
        user = event.get("user", "unknown")
        failed_login_counter[user] += 1

        if failed_login_counter[user] >= 3:
            base_score += 3

    # ========== Suspicious Process Detection ==========
    if event_id == 4688:
        process = event.get("process_name")

        if process:
            process = process.lower()

            for suspicious in SUSPICIOUS_PROCESSES:
                if suspicious in process:
                    base_score += 4
                    break

    # ========== Suspicious Process Chain Heuristic ==========
    base_score = _apply_process_chain_heuristic(event, base_score)

    # ========== Lateral Movement Heuristic ==========
    base_score = _apply_lateral_movement_heuristic(event, base_score)

    return min(base_score, 10)
