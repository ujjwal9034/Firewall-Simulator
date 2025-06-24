from scapy.all import sniff, IP, TCP, UDP
from firewall import load_rules, check_packet
from colorama import Fore, Style, init
import signal
import sys

init(autoreset=True)

# ------------------------------
# Graceful Exit Handling
# ------------------------------
def handle_exit(sig, frame):
    print(Fore.YELLOW + "\n[!] Sniffing stopped by user.")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)

# ------------------------------
# Process and Check Each Packet
# ------------------------------
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]

        if TCP in packet:
            protocol = 'TCP'
            port = packet[TCP].dport
        elif UDP in packet:
            protocol = 'UDP'
            port = packet[UDP].dport
        else:
            protocol = 'OTHER'
            port = 0

        # Convert to standard format
        packet_data = f"{ip_layer.src},{port},{protocol}"

        # Load current rules
        rules = load_rules()
        action, result = check_packet(packet_data, rules)

        color = Fore.GREEN if action == "ALLOW" else Fore.RED
        print(color + f"{action}: Packet {result}")

# ------------------------------
# Start Packet Sniffing
# ------------------------------
def start_sniffing():
    print(Style.BRIGHT + Fore.CYAN + "Firewall Monitor - Sniffing packets...\nPress CTRL+C to stop.\n")
    sniff(filter="ip", prn=process_packet, store=0)

# ------------------------------
# Entry Point
# ------------------------------
if __name__ == "__main__":
    start_sniffing()
