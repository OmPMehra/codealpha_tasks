from scapy.all import sniff, IP, TCP, ICMP, get_if_list
from collections import defaultdict

# Counters
icmp_count = defaultdict(int)
syn_count = defaultdict(int)

# Detection thresholds
ICMP_THRESHOLD = 10
SYN_THRESHOLD = 10


def detect(packet):
    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # ICMP Flood Detection
        if packet.haslayer(ICMP):
            icmp_count[src_ip] += 1

            if icmp_count[src_ip] > ICMP_THRESHOLD:
                print(f"\n[ALERT] Possible ICMP Flood from {src_ip}")

        # TCP Detection
        if packet.haslayer(TCP):

            # SYN Flood Detection
            if packet[TCP].flags == "S":
                syn_count[src_ip] += 1

                if syn_count[src_ip] > SYN_THRESHOLD:
                    print(f"\n[ALERT] Possible SYN Flood from {src_ip}")

            # Suspicious Ports
            if packet[TCP].dport in [21, 23]:
                print(
                    f"\n[WARNING] Connection detected to suspicious port "
                    f"{packet[TCP].dport}"
                )

            # Show traffic
            print(
                f"TCP | {src_ip}:{packet[TCP].sport} "
                f"-> {dst_ip}:{packet[TCP].dport}"
            )


def main():

    print("=" * 50)
    print("Network Intrusion Detection System")
    print("=" * 50)

    iface_list = get_if_list()

    print("\nAvailable Interfaces:\n")

    for i, iface in enumerate(iface_list):
        print(f"{i}. {iface}")

    # Safe input
    while True:
        try:
            choice = int(input("\nSelect interface number: "))

            if 0 <= choice < len(iface_list):
                break

            print("Invalid interface number.")

        except ValueError:
            print("Please enter a valid number.")

    selected_iface = iface_list[choice]

    print(f"\nSelected Interface: {selected_iface}")
    print("Capturing traffic...")
    print("Press CTRL + C to stop.\n")

    try:
        sniff(
            iface=selected_iface,
            prn=detect,
            store=False
        )

    except KeyboardInterrupt:
        print("\n\nIDS Stopped Successfully")


if __name__ == "__main__":
    main()