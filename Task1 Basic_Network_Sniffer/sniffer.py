from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, wrpcap
from datetime import datetime

packet_count = 0
captured_packets = []

stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "OTHER": 0
}


def packet_callback(packet):
    global packet_count

    packet_count += 1
    captured_packets.append(packet)

    timestamp = datetime.now().strftime("%H:%M:%S")

    print("\n" + "=" * 60)
    print(f"Packet #{packet_count} | Time: {timestamp}")
    print("=" * 60)

    if packet.haslayer(IP):

        print("Source IP       :", packet[IP].src)
        print("Destination IP  :", packet[IP].dst)

        if packet.haslayer(TCP):

            stats["TCP"] += 1

            print("Protocol        : TCP")
            print("Source Port     :", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif packet.haslayer(UDP):

            stats["UDP"] += 1

            print("Protocol        : UDP")
            print("Source Port     :", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        elif packet.haslayer(ICMP):

            stats["ICMP"] += 1

            print("Protocol        : ICMP")
            print("Type            :", packet[ICMP].type)
            print("Code            :", packet[ICMP].code)

        else:

            stats["OTHER"] += 1
            print("Protocol        : Other")

    else:
        stats["OTHER"] += 1
        print("Non-IP Packet")


print("=" * 60)
print("BASIC NETWORK SNIFFER")
print("=" * 60)

interfaces = get_if_list()

print("\nAvailable Interfaces:\n")

for i, iface in enumerate(interfaces):
    print(f"{i}. {iface}")

try:

    choice = int(input("\nSelect interface number: "))

    if choice < 0 or choice >= len(interfaces):
        print("Invalid interface selected.")
        exit()

    selected_interface = interfaces[choice]

    print("\nProtocol Filter Options")
    print("1. TCP")
    print("2. UDP")
    print("3. ICMP")
    print("4. All Traffic")

    filter_choice = input("\nEnter choice: ")

    if filter_choice == "1":
        filter_rule = "tcp"
    elif filter_choice == "2":
        filter_rule = "udp"
    elif filter_choice == "3":
        filter_rule = "icmp"
    else:
        filter_rule = None

    print(f"\nSelected Interface: {selected_interface}")
    print("Capturing 50 packets...")
    print("Generate some traffic by opening websites.\n")

    sniff(
        iface=selected_interface,
        prn=packet_callback,
        filter=filter_rule,
        count=50
    )

    print("\n" + "=" * 60)
    print("CAPTURE SUMMARY")
    print("=" * 60)

    print("Total Packets :", packet_count)
    print("TCP Packets   :", stats["TCP"])
    print("UDP Packets   :", stats["UDP"])
    print("ICMP Packets  :", stats["ICMP"])
    print("Other Packets :", stats["OTHER"])

    save_choice = input("\nSave packets to PCAP file? (y/n): ")

    if save_choice.lower() == "y":

        filename = input("Enter file name: ").strip()

        if not filename:
            filename = "capture"

        if not filename.endswith(".pcap"):
            filename += ".pcap"

        wrpcap(filename, captured_packets)

        print(f"\nPackets saved successfully to '{filename}'")

except ValueError:
    print("Please enter a valid number.")

except Exception as e:
    print("Error:", e)