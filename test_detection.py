from database import get_connection
from detection_engine import detect_high_traffic
from datetime import datetime

# Use a reserved documentation IP for testing
test_ip = "192.0.2.12"

connection = get_connection()
cursor = connection.cursor()

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

print("Creating 100 test packets...")

# Insert 100 artificial packet records
for i in range(100):
    cursor.execute("""
        INSERT INTO network_traffic
        (timestamp, source_ip, destination_ip, protocol, packet_size)
        VALUES (?, ?, ?, ?, ?)
    """, (
        timestamp,
        test_ip,
        "192.0.2.20",
        "TCP",
        100
    ))

connection.commit()
connection.close()

print("100 test packets inserted.")

# Run our custom detection engine
detect_high_traffic(test_ip)

# Check whether an alert was generated
connection = get_connection()
cursor = connection.cursor()

cursor.execute("""
    SELECT source_ip, attack_type, severity, risk_score
    FROM security_alerts
    WHERE source_ip = ?
    ORDER BY id DESC
    LIMIT 1
""", (test_ip,))

alert = cursor.fetchone()

if alert:
    print("\nSUCCESS! Security alert found:")
    print(dict(alert))
else:
    print("\nNo alert generated. Check the detection code.")

connection.close()