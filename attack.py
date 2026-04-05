from scapy.all import send, IP, TCP, Raw

# Yahan humne Sniffer wala IP dala hai (Jo aapki screen par dikh raha tha)
target_ip = "127.0.0.1"

print(f"🔥 Sending Attack Packets to {target_ip}...")

# Attack Packet: Port 666 (Suspicious) + Safe Size (1000 bytes)
# Note: Humne size 50000 se kam karke 1000 kiya hai taaki Error na aaye.
packet = IP(src="45.33.22.11", dst=target_ip)/TCP(dport=80, flags="FPU")/Raw(load="X"*1500)

send(packet, verbose=False)
print("✅ Attack Sent!")
