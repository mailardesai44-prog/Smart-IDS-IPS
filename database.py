import sqlite3

DATABASE = "smart_ids.db"


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_tables():

    connection = get_connection()
    cursor = connection.cursor()

    # Network Traffic Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        packet_size INTEGER
    )
    """)

    # Security Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        attack_type TEXT,
        severity TEXT,
        description TEXT,
        risk_score INTEGER
    )
    """)

    # Blocked IP Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE,
        reason TEXT,
        blocked_at TEXT,
        status TEXT DEFAULT 'Active'
    )
    """)

    connection.commit()
    connection.close()

    print("Database created successfully!")
    print("All security tables created successfully!")


if __name__ == "__main__":
    create_tables()