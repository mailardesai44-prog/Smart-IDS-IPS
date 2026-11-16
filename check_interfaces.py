from scapy.all import conf

print("\nNETWORK INTERFACE DETAILS")
print("=" * 70)

for interface in conf.ifaces.values():
    print("Name:", interface.name)
    print("Description:", interface.description)
    print("IP Address:", interface.ip)
    print("-" * 70)