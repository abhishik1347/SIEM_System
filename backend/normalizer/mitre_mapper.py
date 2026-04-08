def map_to_mitre(event_id):

    mitre_map = {
        4624: "Lateral Movement - Remote Services",
        4625: "Credential Access - Brute Force",
        4672: "Privilege Escalation",
        4720: "Persistence - Create Account",
        4728: "Privilege Escalation - Account Manipulation",
        4732: "Privilege Escalation - Account Manipulation",
        4756: "Privilege Escalation - Account Manipulation",
        4697: "Persistence - Service Installation",
        1102: "Defense Evasion - Log Clearing",
        4688: "Execution - Command & Scripting Interpreter"
    }

    return mitre_map.get(event_id, "Unknown")
