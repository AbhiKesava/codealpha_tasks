sniffer.py
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):

    print("\n==============================")
    print("Packet Captured")

    if packet.haslayer(IP):

        ip_layer = packet[IP]

        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol Number: {ip_layer.proto}")

        if packet.haslayer(TCP):
            print("Protocol Name  : TCP")

        elif packet.haslayer(UDP):
            print("Protocol Name  : UDP")

        elif packet.haslayer(ICMP):
            print("Protocol Name  : ICMP")

        if packet.haslayer(Raw):
            print("Payload Data:")
            print(packet[Raw].load)

    print("==============================")

print("Starting Network Sniffer...")

sniff(prn=packet_callback, store=False)
