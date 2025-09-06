from scapy.all import *

# Let's see what's on your network interface
packet = sniff(count=1)[0]  # Capture just one packet
print(packet.show())