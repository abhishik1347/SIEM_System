from collections import defaultdict

def aggregate_by_user(logs):

    user_risk = defaultdict(int)

    for log in logs:
        user = log.get("user")

        if not user or user == "None":
            continue

        user_risk[user] += log.get("risk", 0)

    return user_risk
