from collections import defaultdict

failed_login_counter = defaultdict(int)

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
    4697: 8,
    1102: 10,
    4688: 4
}

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

    return min(base_score, 10)
