from collections import defaultdict
import statistics

# Historical storage
user_total_history = defaultdict(list)
previous_total_risk = defaultdict(int)

# Anomaly memory
anomaly_state = defaultdict(lambda: {"active": False, "cooldown": 0})

COOLDOWN_CYCLES = 3
SPIKE_THRESHOLD = 10
Z_THRESHOLD = 2


def detect_anomaly(user, current_total_risk):

    if not user:
        return False, 0, 0

    # ================= SPIKE DETECTION =================
    previous = previous_total_risk[user]
    delta = current_total_risk - previous
    previous_total_risk[user] = current_total_risk

    spike_flag = delta >= SPIKE_THRESHOLD

    # ================= STATISTICAL DETECTION =================
    history = user_total_history[user]
    z_score = 0
    statistical_flag = False

    if len(history) >= 5:
        avg = statistics.mean(history)
        std_dev = statistics.stdev(history) if len(history) > 1 else 0

        if std_dev > 0:
            z_score = (current_total_risk - avg) / std_dev
            if z_score > Z_THRESHOLD:
                statistical_flag = True

    user_total_history[user].append(current_total_risk)

    # ================= HYBRID DECISION =================
    if spike_flag or statistical_flag:
        anomaly_state[user]["active"] = True
        anomaly_state[user]["cooldown"] = COOLDOWN_CYCLES

    # ================= COOLDOWN LOGIC =================
    if anomaly_state[user]["active"]:
        anomaly_state[user]["cooldown"] -= 1

        if anomaly_state[user]["cooldown"] <= 0:
            anomaly_state[user]["active"] = False

    anomaly_flag = anomaly_state[user]["active"]

    # Confidence score
    confidence = round(abs(z_score) + delta, 2)

    return anomaly_flag, round(z_score, 2), confidence
