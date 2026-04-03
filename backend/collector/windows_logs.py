import win32evtlog

def get_system_logs(limit=20):

    server = 'localhost'
    logtype = 'Security'   # Use System log for development

    handle = win32evtlog.OpenEventLog(server, logtype)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    logs = []
    total = 0

    while True:
        events = win32evtlog.ReadEventLog(handle, flags, 0)

        if not events:
            break

        for event in events:

            event_id = event.EventID & 0xFFFF

            logs.append({
                "event_id": event_id,
                "source": event.SourceName,
                "time": str(event.TimeGenerated),
                "data": event.StringInserts
            })

            total += 1

            if total >= limit:
                return logs

    return logs
