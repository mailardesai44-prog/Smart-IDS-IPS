
from flask import Flask, render_template, redirect, url_for
from database import get_connection, create_tables
from prevention_engine import unblock_ip
from datetime import datetime, timedelta

app = Flask(__name__)

# Create database tables
create_tables()


@app.route('/')
def home():

    connection = get_connection()
    cursor = connection.cursor()

    # Total network packets
    cursor.execute("SELECT COUNT(*) FROM network_traffic")
    total_packets = cursor.fetchone()[0]

    # Get latest 10 network packets
    cursor.execute("""
        SELECT timestamp, source_ip, destination_ip, protocol, packet_size
        FROM network_traffic
        ORDER BY id DESC
        LIMIT 10
    """)
    recent_packets = cursor.fetchall()

    # Network protocol statistics
    cursor.execute("""
        SELECT protocol, COUNT(*) AS total
        FROM network_traffic
        GROUP BY protocol
    """)
    protocol_stats = cursor.fetchall()

    protocol_counts = {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "OTHER": 0
    }

    for item in protocol_stats:
        protocol = item["protocol"]

        if protocol in protocol_counts:
            protocol_counts[protocol] = item["total"]
        else:
            protocol_counts["OTHER"] += item["total"]

    # Total detected threats
    cursor.execute("SELECT COUNT(*) FROM security_alerts")
    total_threats = cursor.fetchone()[0]

    # Total active blocked IPs
    cursor.execute("""
        SELECT COUNT(*)
        FROM blocked_ips
        WHERE status = 'Active'
    """)
    blocked_ips = cursor.fetchone()[0]

    # Get latest 10 blocked IP addresses
    cursor.execute("""
        SELECT ip_address, reason, blocked_at, status
        FROM blocked_ips
        ORDER BY id DESC
        LIMIT 10
    """)
    recent_blocked_ips = cursor.fetchall()

    # Total security alerts
    total_alerts = total_threats

    # Get latest 10 security alerts
    cursor.execute("""
        SELECT timestamp, source_ip, attack_type, severity, risk_score
        FROM security_alerts
        ORDER BY id DESC
        LIMIT 10
    """)
    recent_alerts = cursor.fetchall()

    # Count security alerts by severity
    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM security_alerts
        GROUP BY severity
    """)
    severity_data = cursor.fetchall()

    risk_counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for severity, count in severity_data:
        if severity in risk_counts:
            risk_counts[severity] = count

    # =====================================
    # DYNAMIC SYSTEM STATUS
    # =====================================

    # Network monitoring status
    cursor.execute("""
        SELECT timestamp
        FROM network_traffic
        ORDER BY id DESC
        LIMIT 1
    """)

    latest_packet = cursor.fetchone()

    monitoring_status = "Inactive"
    monitoring_message = "No recent network packets received."

    if latest_packet and latest_packet["timestamp"]:

        try:
            packet_time = datetime.strptime(
                latest_packet["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            if datetime.now() - packet_time <= timedelta(seconds=30):
                monitoring_status = "Active"
                monitoring_message = "Recent network packets are being recorded."

        except ValueError:
            monitoring_message = "Unable to verify the latest packet timestamp."

    # Threat detection status based on recorded alerts
    if total_threats > 0:
        detection_status = "Alerts Found"
        detection_message = (
            f"{total_threats} security alert(s) recorded in the database."
        )
    else:
        detection_status = "No Alerts"
        detection_message = "No security alerts have been recorded."

    # Intrusion prevention status
    if blocked_ips > 0:
        prevention_status = "Active"
        prevention_message = (
            f"{blocked_ips} IP address(es) currently marked as blocked."
        )
    else:
        prevention_status = "No Active Blocks"
        prevention_message = "No IP addresses are currently blocked."

    connection.close()

    return render_template(
        'index.html',
        total_packets=total_packets,
        total_threats=total_threats,
        blocked_ips=blocked_ips,
        total_alerts=total_alerts,
        recent_packets=recent_packets,
        recent_alerts=recent_alerts,
        recent_blocked_ips=recent_blocked_ips,
        protocol_counts=protocol_counts,
        risk_counts=risk_counts,

        # Dynamic status variables
        monitoring_status=monitoring_status,
        monitoring_message=monitoring_message,
        detection_status=detection_status,
        detection_message=detection_message,
        prevention_status=prevention_status,
        prevention_message=prevention_message
    )


@app.route('/unblock/<ip_address>', methods=['POST'])
def unblock_ip_route(ip_address):

    unblock_ip(ip_address)

    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
