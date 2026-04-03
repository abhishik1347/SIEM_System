def parse_windows_event(log):

    parsed = {
        "event_id": log["event_id"],
        "time": log["time"],
        "user": None,
        "action": "other",
        "process_name": None
    }

    event_id = log["event_id"]

    # ================= Action Mapping =================
    if event_id == 4624:
        parsed["action"] = "login_success"

    elif event_id == 4625:
        parsed["action"] = "login_failed"

    elif event_id == 4672:
        parsed["action"] = "admin_privilege"

    elif event_id == 4720:
        parsed["action"] = "user_created"

    elif event_id == 4697:
        parsed["action"] = "service_installed"

    elif event_id == 1102:
        parsed["action"] = "log_cleared"

    elif event_id == 4688:
        parsed["action"] = "process_created"

    # ================= Extract Data =================
    if log["data"]:

        try:
            if event_id in [4624, 4625]:
                parsed["user"] = log["data"][5]

            elif event_id in [4672, 4720]:
                parsed["user"] = log["data"][1]

            elif event_id == 4688:
                parsed["user"] = log["data"][1]
                parsed["process_name"] = log["data"][5]  # New process name

        except:
            pass

    return parsed
