from database import get_connection

connection = get_connection()
cursor = connection.cursor()

cursor.execute("SELECT COUNT(*) FROM network_traffic")

total = cursor.fetchone()[0]

print("================================")
print("SMART IDS - PACKET DATABASE")
print("================================")
print("Total Captured Packets:", total)

cursor.execute("""
SELECT timestamp, source_ip, destination_ip, protocol, packet_size
FROM network_traffic
ORDER BY id DESC
LIMIT 10
""")

print("\nLatest 10 Packets:\n")

for packet in cursor.fetchall():
    print(dict(packet))

connection.close()