from prevention_engine import unblock_ip, get_blocked_ips

test_ip = "192.0.2.50"

print("SMART IDS/IPS - UNBLOCK TEST")
print("----------------------------")

# Unblock the test IP
unblock_ip(test_ip)

# Display updated blocklist
print("\nUpdated Blocklist:")

for item in get_blocked_ips():
    print(dict(item))

print("\nUnblock test completed.")