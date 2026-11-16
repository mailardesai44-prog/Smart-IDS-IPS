from database import get_connection
from datetime import datetime


def block_ip(ip_address, reason):

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("""
            INSERT OR IGNORE INTO blocked_ips
            (ip_address, reason, blocked_at, status)
            VALUES (?, ?, ?, ?)
        """, (
            ip_address,
            reason,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Active"
        ))

        connection.commit()

        if cursor.rowcount > 0:
            print("IP added to simulated blocklist!")
            print("IP Address:", ip_address)
        else:
            print("IP is already in the blocklist.")

    finally:
        connection.close()


def get_blocked_ips():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT ip_address, reason, blocked_at, status
        FROM blocked_ips
        ORDER BY id DESC
    """)

    blocked_list = cursor.fetchall()

    connection.close()

    return blocked_list
def unblock_ip(ip_address):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE blocked_ips
        SET status = 'Unblocked'
        WHERE ip_address = ?
        AND status = 'Active'
    """, (ip_address,))

    connection.commit()

    if cursor.rowcount > 0:
        print("IP successfully unblocked!")
        print("IP Address:", ip_address)
    else:
        print("Active IP address not found.")

    connection.close()