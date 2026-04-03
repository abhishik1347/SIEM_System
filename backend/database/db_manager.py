import mysql.connector

# Update with your credentials
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Abhishik@1347",
    "database": "siem_db"
}


def get_connection():
    return mysql.connector.connect(**DB_CONFIG)


def insert_log(event):

    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT IGNORE INTO logs (
            event_id, time, user, action,
            risk, category, mitre, anomaly
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """

    values = (
        event["event_id"],
        event["time"],
        event["user"],
        event["action"],
        event["risk"],
        event["ocsf"]["category"],
        event["mitre"],
        event["anomaly"]
    )

    cursor.execute(query, values)
    conn.commit()

    cursor.close()
    conn.close()
