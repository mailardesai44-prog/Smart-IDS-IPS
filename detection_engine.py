
from database import get_connection
from prevention_engine import block_ip
from datetime import datetime, timedelta


def detect_high_traffic(source_ip):

    connection = get_connection()

    try:
        cursor = connection.cursor()

        # Calculate the last 10 seconds
        cutoff_time = (
            datetime.now() - timedelta(seconds=10)
        ).strftime("%Y-%m-%d %H:%M:%S")

        # Count packets from this source IP
        cursor.execute("""
            SELECT COUNT(*)
            FROM network_traffic
            WHERE source_ip = ?
            AND timestamp >= ?
        """, (source_ip, cutoff_time))

        packet_count = cursor.fetchone()[0]

        # Detection threshold
        if packet_count >= 100:

            # Check the 60-second alert cooldown
            recent_alert_time = (
                datetime.now() - timedelta(seconds=60)
            ).strftime("%Y-%m-%d %H:%M:%S")

            cursor.execute("""
                SELECT COUNT(*)
                FROM security_alerts
                WHERE source_ip = ?
                AND attack_type = ?
                AND timestamp >= ?
            """, (
                source_ip,
                "High Traffic Activity",
                recent_alert_time
            ))

            existing_alert = cursor.fetchone()[0]

            if existing_alert == 0:

                # Generate security alert
                cursor.execute("""
                    INSERT INTO security_alerts
                    (
                        timestamp,
                        source_ip,
                        attack_type,
                        severity,
                        description,
                        risk_score
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    source_ip,
                    "High Traffic Activity",
                    "High",
                    "Source IP generated 100 or more packets within 10 seconds.",
                    80
                ))

                connection.commit()

                # Automatically add IP to simulated blocklist
                block_ip(
                    source_ip,
                    "Automatically added due to high traffic activity"
                )

                print("SECURITY ALERT GENERATED!")
                print("Source IP:", source_ip)
                print("Packets:", packet_count)

    finally:
        connection.close()
