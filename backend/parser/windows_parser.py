def _safe_data_get(data, index):
    try:
        if data and len(data) > index:
            return data[index]
    except Exception:
        return None
    return None


def parse_windows_event(log):

    parsed = {
        "event_id": log["event_id"],
        "time": log["time"],
        "user": None,
        "action": "other",
        "process_name": None,
        "process_parent": None,
        "logon_type": None,
        "group_name": None,
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

    elif event_id in [4728, 4732, 4756]:
        parsed["action"] = "privileged_group_change"

    # ================= Extract Data =================
    if log["data"]:

        try:
            if event_id in [4624, 4625]:
                parsed["user"] = _safe_data_get(log["data"], 5)
                parsed["logon_type"] = _safe_data_get(log["data"], 8)
                if event_id == 4624 and str(parsed["logon_type"]).strip() in {"3", "10"}:
                    parsed["action"] = "remote_login_success"

            elif event_id in [4672, 4720]:
                parsed["user"] = _safe_data_get(log["data"], 1)

            elif event_id == 4688:
                parsed["user"] = _safe_data_get(log["data"], 1)
                parsed["process_name"] = _safe_data_get(log["data"], 5)
                parsed["process_parent"] = _safe_data_get(log["data"], 13)

            elif event_id in [4728, 4732, 4756]:
                # Commonly: member account around index 0/1 and group name around 2/3,
                # but exact index varies by Windows build/localization.
                parsed["user"] = _safe_data_get(log["data"], 0) or _safe_data_get(log["data"], 1)
                parsed["group_name"] = _safe_data_get(log["data"], 2) or _safe_data_get(log["data"], 3)

        except:
            pass

    return parsed
