from prevention_engine import block_ip, get_blocked_ips

# Test IP address (reserved for documentation)
test_ip = "192.0.2.50"

print("SMART IDS/IPS - PREVENTION TEST")
print("--------------------------------")

# Add IP to simulated blocklist
block_ip(
    test_ip,
    "Manual prevention testing"
)

# Display blocked IP addresses
print("\nCurrent Simulated Blocklist:")

blocked_list = get_blocked_ips()

for item in blocked_list:
    print(dict(item))

print("\nPrevention test completed.")