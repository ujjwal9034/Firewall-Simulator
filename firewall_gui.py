import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk
import os
import datetime
import platform
import threading
import queue
from scapy.all import sniff, IP, TCP, UDP
import smtplib
from email.mime.text import MIMEText
from PIL import Image

if platform.system() == "Windows":
    import winsound

RULES_PATH = "./data/rules.txt"
PACKETS_PATH = "./data/packets.txt"
LOG_PATH = "./logs/firewall_log.txt"

EMAIL_ADDRESS = "ujjwalchauhan671@gmail.com"
EMAIL_PASSWORD = "pvnx ejmv jpav mfld"
TO_EMAIL = "ujjwalchauhan599@gmail.com"

packet_queue = queue.Queue()
stop_sniffing_event = threading.Event()


def load_rules():
    rules = []
    try:
        with open(RULES_PATH, 'r') as file:
            for line in file:
                parts = line.strip().split(',')
                if len(parts) == 4:
                    rules.append(parts)
    except FileNotFoundError:
        pass
    return rules


def send_email_alert(packet_info):
    try:
        msg = MIMEText(f"\U000026A0\ufe0f BLOCKED Packet:\n\n{packet_info}")
        msg['Subject'] = "Firewall Alert: Blocked Packet Detected"
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = TO_EMAIL

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        print(f"[!] Email alert failed: {e}")


def check_packet(packet, rules):
    for rule in rules:
        action, ip, port, proto = rule
        if (ip == packet[0] or ip == "*") and (port == packet[1] or port == "*") and (proto.upper() == packet[2].upper() or proto == "*"):
            return f"{action}: {','.join(packet)}"
    return f"BLOCK (default): {','.join(packet)}"


def save_log(entry):
    with open(LOG_PATH, 'a') as log_file:
        log_file.write(f"{datetime.datetime.now()}: {entry}\n")


def process_packet(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        proto = 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'OTHER'
        port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else '0'
        packet_str = f"{ip_layer.src},{port},{proto}"
        packet_queue.put(packet_str)


def start_sniffing():
    stop_sniffing_event.clear()
    sniff(filter="ip", prn=process_packet, store=0, stop_filter=lambda x: stop_sniffing_event.is_set())


def create_entry(frame, placeholder, show=None):
    entry = tk.Entry(frame, font=("Segoe UI", 10), bg="#f0f0f0", relief="flat", show=show)
    entry.insert(0, placeholder)
    entry.bind("<FocusIn>", lambda e: entry.delete(0, tk.END) if entry.get() == placeholder else None)
    return entry


def login_screen():
    global login_win, background_label_login, background_image_login

    login_win = tk.Tk()
    login_win.title("\U0001F510 Firewall Simulator - Login")
    login_win.geometry("400x300")
    login_win.resizable(True, True)

    bg_login_path = "background_login.png"
    if os.path.exists(bg_login_path):
        bg_img = Image.open(bg_login_path)
        bg_img = bg_img.resize((400, 300), Image.Resampling.LANCZOS)
        background_image_login = ImageTk.PhotoImage(bg_img)
        background_label_login = tk.Label(login_win, image=background_image_login)
        background_label_login.place(x=0, y=0, relwidth=1, relheight=1)
    else:
        login_win.configure(bg="#ffffff")

    frame = tk.Frame(login_win, bg="#ffffff")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    tk.Label(frame, text="Username:", bg="#ffffff", font=("Segoe UI", 12)).grid(row=0, column=0, pady=10, sticky="e")
    username_entry = create_entry(frame, "Enter username")
    username_entry.grid(row=0, column=1, pady=10)

    tk.Label(frame, text="Password:", bg="#ffffff", font=("Segoe UI", 12)).grid(row=1, column=0, pady=10, sticky="e")
    password_entry = create_entry(frame, "Enter password", show="*")
    password_entry.grid(row=1, column=1, pady=10)

    def check_login(event=None):
        user = username_entry.get().strip()
        pwd = password_entry.get().strip()
        if user == "admin" and pwd == "admin123":
            login_win.destroy()
            launch_main_app()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    login_btn = ttk.Button(frame, text="Login", command=check_login)
    login_btn.grid(row=2, column=0, columnspan=2, pady=20, ipadx=20)

    # 🔁 Enter key navigation
    username_entry.bind("<Return>", lambda e: password_entry.focus_set())
    password_entry.bind("<Return>", check_login)

    # Autofocus on username
    username_entry.focus_set()

    login_win.mainloop()


def launch_main_app():
    global window, background_label_main, original_bg_img, background_image_main
    
    window = tk.Tk()
    window.title("🛡 Firewall Simulator")
    window.geometry("960x700")
    window.resizable(True, True)  # Allow resizing now

    bg_main_path = "background_main.png"
    if os.path.exists(bg_main_path):
        original_bg_img = Image.open(bg_main_path)
        background_image_main = ImageTk.PhotoImage(original_bg_img)
        background_label_main = tk.Label(window, image=background_image_main)
        background_label_main.place(x=0, y=0, relwidth=1, relheight=1)
    else:
        window.configure(bg="#ffffff")

    def resize_background(event):
        new_width = event.width
        new_height = event.height
        resized = original_bg_img.resize((new_width, new_height), Image.LANCZOS)
        background_image_main_resized = ImageTk.PhotoImage(resized)
        background_label_main.configure(image=background_image_main_resized)
        background_label_main.image = background_image_main_resized  # keep reference

    window.bind("<Configure>", resize_background)
    
    style = ttk.Style()
    style.configure("TButton", font=("Segoe UI", 10), padding=6, relief="flat", background="#0078d7", foreground="black")
    style.map("TButton", foreground=[("active", "black")], background=[("active", "#005a9e")])
    style.configure("TLabel", font=("Segoe UI", 10), background="#ffffff")

    def section_label(text):
        return tk.Label(window, text=text, bg="#ffffff", fg="#0078d7", font=("Segoe UI", 14, "bold"))

    section_label("\u2795 Add Rule").pack(pady=(15, 5))
    add_frame = tk.Frame(window, bg="#ffffff")
    add_frame.pack(pady=5)

    action_var = tk.StringVar(value="ALLOW")
    action_menu = ttk.Combobox(add_frame, textvariable=action_var, values=["ALLOW", "BLOCK"], width=10, state="readonly")
    action_menu.grid(row=0, column=0, padx=5)

    ip_entry = create_entry(add_frame, "IP Address (e.g. 192.168.1.1)")
    ip_entry.grid(row=0, column=1, padx=5)
    port_entry = create_entry(add_frame, "Port (e.g. 80)")
    port_entry.grid(row=0, column=2, padx=5)
    proto_entry = create_entry(add_frame, "Protocol (TCP/UDP)")
    proto_entry.grid(row=0, column=3, padx=5)

    def add_rule():
        ip_placeholder = "IP Address (e.g. 192.168.1.1)"
        port_placeholder = "Port (e.g. 80)"
        proto_placeholder = "Protocol (TCP/UDP)"

        action = action_var.get()
        ip = ip_entry.get().strip()
        port = port_entry.get().strip()
        proto = proto_entry.get().strip().upper()

        if ip == ip_placeholder or port == port_placeholder or proto == proto_placeholder:
            messagebox.showerror("Error", "Please fill in all fields correctly, not placeholder values.")
            return

        if not action or not ip or not port or not proto:
            messagebox.showerror("Error", "All fields must be filled.")
            return

        with open(RULES_PATH, 'a') as rf, open(PACKETS_PATH, 'a') as pf:
            rf.write(f"{action},{ip},{port},{proto}\n")
            pf.write(f"{ip},{port},{proto}\n")

        ip_entry.delete(0, tk.END)
        port_entry.delete(0, tk.END)
        proto_entry.delete(0, tk.END)
        ip_entry.insert(0, ip_placeholder)
        port_entry.insert(0, port_placeholder)
        proto_entry.insert(0, proto_placeholder)

        run_simulation()
        messagebox.showinfo("Success", "Rule added and simulation updated!")


    add_btn = ttk.Button(add_frame, text="Add", command=add_rule)
    add_btn.grid(row=0, column=4, padx=5)

    section_label("\U0001F4CB Simulation Logs").pack(pady=(15, 5))
    log_box = tk.Listbox(window, height=10, bg="#f9f9f9", font=("Consolas", 10), borderwidth=0)
    log_box.pack(fill="both", expand=True, padx=20, pady=5)

    def run_simulation():
        log_box.delete(0, tk.END)  # Clear old simulation logs

        if not os.path.exists(RULES_PATH):
            messagebox.showerror("Missing", "Rules file not found.")
            return
        if not os.path.exists(PACKETS_PATH):
            messagebox.showerror("Missing", "Packets file not found.")
            return

        rules = load_rules()

        with open(PACKETS_PATH, 'r') as pf:
            for line in pf:
                parts = line.strip().split(',')
                if len(parts) == 3:
                    result = check_packet(parts, rules)
                    log_box.insert(tk.END, result)
                    save_log(result)



    run_btn = ttk.Button(window, text="Run Simulation", command=run_simulation)
    run_btn.pack(pady=10)

    section_label("\U0001F9EA Test Packet").pack(pady=(20, 5))
    test_frame = tk.Frame(window, bg="#ffffff")
    test_frame.pack()

    test_ip = create_entry(test_frame, "IP")
    test_ip.grid(row=0, column=0, padx=5)
    test_port = create_entry(test_frame, "Port")
    test_port.grid(row=0, column=1, padx=5)
    test_proto = create_entry(test_frame, "Protocol")
    test_proto.grid(row=0, column=2, padx=5)

    def test_packet():
        packet = [test_ip.get().strip(), test_port.get().strip(), test_proto.get().strip().upper()]
        result = check_packet(packet, load_rules())
        save_log("[LIVE TEST] " + result)
        if result.startswith("BLOCK"):
            threading.Thread(target=send_email_alert, args=(','.join(packet),), daemon=True).start()
            if platform.system() == "Windows":
                winsound.MessageBeep(type=winsound.MB_ICONEXCLAMATION)
        messagebox.showinfo("Test Result", result)

    test_btn = ttk.Button(test_frame, text="Test", command=test_packet)
    test_btn.grid(row=0, column=3, padx=5)

    section_label("\U0001F50D Live Monitoring").pack(pady=(15, 5))
    monitor_box = tk.Listbox(window, height=10, bg="#eef5f9", font=("Consolas", 10), borderwidth=0)
    monitor_box.pack(fill="both", expand=True, padx=20, pady=5)

    monitor_frame = tk.Frame(window, bg="#ffffff")
    monitor_frame.pack(pady=10)

    def update_monitor():
        while not stop_sniffing_event.is_set():
            try:
                packet = packet_queue.get(timeout=1)
                result = check_packet(packet.split(','), load_rules())
                monitor_box.insert(tk.END, result)
                save_log("[MONITOR] " + result)
            except queue.Empty:
                continue

    def start_monitor():
        stop_sniffing_event.clear()
        threading.Thread(target=start_sniffing, daemon=True).start()
        threading.Thread(target=update_monitor, daemon=True).start()

    def stop_monitor():
        stop_sniffing_event.set()

    ttk.Button(monitor_frame, text="Start Monitoring", command=start_monitor).grid(row=0, column=0, padx=10)
    ttk.Button(monitor_frame, text="Stop Monitoring", command=stop_monitor).grid(row=0, column=1, padx=10)

    window.mainloop()


if __name__ == "__main__":
    login_screen()
