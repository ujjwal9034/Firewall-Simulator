from colorama import Fore, Style, init
import smtplib
from email.mime.text import MIMEText
import os
import threading
from scapy.all import sniff, IP, TCP, UDP

init(autoreset=True)

# ------------------------------
# File Paths
# ------------------------------
RULE_FILE = './data/rules.txt'
PACKET_FILE = './data/packets.txt'
LOG_FILE = './logs/firewall_log.txt'

# ------------------------------
# Email Configuration
# ------------------------------
EMAIL_ADDRESS = "ujjwalchauhan671@gmail.com"
EMAIL_PASSWORD = "pvnx ejmv jpav mfld"
TO_EMAIL = "ujjwalchauhan599@gmail.com"

# ------------------------------
# Load Rules from File
# ------------------------------
def load_rules(filename=RULE_FILE):
    rules = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                action, ip, port, protocol = line.strip().split(',')
                rules.append((action.upper(), ip, port, protocol.upper()))
    except FileNotFoundError:
        pass
    return rules

# ------------------------------
# Send Email Alert (thread-safe)
# ------------------------------
def send_email_alert(packet_info):
    def send():
        try:
            msg = MIMEText(f"⚠️ BLOCKED Packet:\n\n{packet_info}")
            msg['Subject'] = "Firewall Alert: Blocked Packet Detected"
            msg['From'] = EMAIL_ADDRESS
            msg['To'] = TO_EMAIL

            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                smtp.send_message(msg)
        except Exception as e:
            print(Fore.YELLOW + f"[!] Email alert failed: {e}")
    threading.Thread(target=send).start()

# ------------------------------
# Check a Packet Against Rules
# ------------------------------
def check_packet(packet, rules, email_alert=False):
    src_ip, port, protocol = packet.strip().split(',')
    for action, rule_ip, rule_port, rule_protocol in rules:
        if (rule_ip == src_ip or rule_ip == '*') and \
           (rule_port == port or rule_port == '*') and \
           (rule_protocol == protocol.upper() or rule_protocol == '*'):
            if action == "BLOCK" and email_alert:
                send_email_alert(packet)
            return action, packet
    # No matching rule found - do NOT block by default; just ignore
    return None, packet


# ------------------------------
# Simulated Firewall Mode
# ------------------------------
def simulate_firewall():
    with open(PACKET_FILE, 'r') as file:
        packets = file.readlines()

    print("DEBUG: Contents of packets.txt:")
    for line in packets:
        print(f"'{line.strip()}'")

    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE) 
    rules = load_rules()
    if not os.path.exists(PACKET_FILE):
        print(Fore.RED + f"Missing packet file: {PACKET_FILE}")
        return

    with open(PACKET_FILE, 'r') as file:
        packets = file.readlines()

    # DEBUG: print what packets.txt contains
    print(Fore.CYAN + "DEBUG: Packets read from packets.txt:")
    for p in packets:
        print(Fore.CYAN + p.strip())

    allow_count = 0
    block_count = 0

    print("Firewall Simulation Result:\n")
    with open(LOG_FILE, 'w') as log:
        for packet in packets:
            action, pkt = check_packet(packet.strip(), rules, email_alert=True)
            if action:
                color = Fore.GREEN if action == "ALLOW" else Fore.RED
                print(color + f"{action}: Packet {pkt.strip()}")
                log.write(f"{action}: {pkt.strip()}\n")
                if action == "ALLOW":
                    allow_count += 1
                else:
                    block_count += 1

    print(Style.BRIGHT + f"\nSummary: {allow_count} Allowed | {block_count} Blocked\n")


# ------------------------------
# Live Test Mode (User Input)
# ------------------------------
def live_mode(rules):
    print("Live Mode: Enter packet as IP,PORT,PROTOCOL (or type 'exit' to quit)\n")
    while True:
        user_input = input("> ")
        if user_input.lower() == "exit":
            break
        threading.Thread(target=handle_live_input, args=(user_input, rules)).start()

def handle_live_input(user_input, rules):
    action, pkt = check_packet(user_input, rules, email_alert=False)
    color = Fore.GREEN if action == "ALLOW" else Fore.RED
    print(color + f"{action}: Packet {pkt}")

# ------------------------------
# Live Packet Monitoring (Sniffing)
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
        packet_data = f"{ip_layer.src},{port},{protocol}"
        rules = load_rules()
        action, pkt = check_packet(packet_data, rules, email_alert=False)
        color = Fore.GREEN if action == "ALLOW" else Fore.RED
        print(color + f"{action}: Packet {pkt}")

def start_sniffing():
    print("Sniffing packets... Press CTRL+C to stop.\n")
    sniff(filter="ip", prn=process_packet, store=0)

# ------------------------------
# Main Entry
# ------------------------------
if __name__ == "__main__":
    rules = load_rules()
    print("1. Simulate Firewall")
    print("2. Live Mode (manual input)")
    print("3. Start Sniffing (Scapy)")
    mode = input("Select Mode [1/2/3]: ")

    if mode == "1":
        simulate_firewall()
    elif mode == "2":
        live_mode(rules)
    elif mode == "3":
        start_sniffing()
    else:
        print(Fore.RED + "Invalid option.")
