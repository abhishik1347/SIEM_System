def to_ocsf(event):

    ocsf_event = {
        "class_uid": 0,
        "category": "unknown",
        "activity_name": "unknown",
        "severity": "low",
        "time": event["time"],
        "user": event["user"]
    }

    event_id = event["event_id"]

    if event_id == 4624:
        ocsf_event["class_uid"] = 3002
        ocsf_event["category"] = "Authentication"
        ocsf_event["activity_name"] = "Logon Success"
        ocsf_event["severity"] = "low"

    elif event_id == 4625:
        ocsf_event["class_uid"] = 3002
        ocsf_event["category"] = "Authentication"
        ocsf_event["activity_name"] = "Logon Failure"
        ocsf_event["severity"] = "medium"

    elif event_id == 4672:
        ocsf_event["class_uid"] = 3004
        ocsf_event["category"] = "Privilege"
        ocsf_event["activity_name"] = "Admin Logon"
        ocsf_event["severity"] = "high"

    elif event_id == 4720:
        ocsf_event["class_uid"] = 3005
        ocsf_event["category"] = "Account Management"
        ocsf_event["activity_name"] = "User Created"
        ocsf_event["severity"] = "high"

    elif event_id == 4720:
        ocsf_event["class_uid"] = 3005
        ocsf_event["category"] = "Account Management"
        ocsf_event["activity_name"] = "User Created"
        ocsf_event["severity"] = "high"

    elif event_id == 4697:
        ocsf_event["class_uid"] = 3006
        ocsf_event["category"] = "Persistence"
        ocsf_event["activity_name"] = "Service Installed"
        ocsf_event["severity"] = "high"

    elif event_id == 1102:
        ocsf_event["class_uid"] = 3007
        ocsf_event["category"] = "Defense Evasion"
        ocsf_event["activity_name"] = "Audit Log Cleared"
        ocsf_event["severity"] = "critical"


    return ocsf_event
