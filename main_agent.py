import time
from collections import defaultdict
from scapy.all import sniff, IP
import csv
import os
MAX_LOG_LINES = 1000
# -----------------------------
# Attack tracking structures
# -----------------------------

attack_counter = defaultdict(int)
attack_start_time = defaultdict(float)

# -----------------------------
# Log file for dashboard
# -----------------------------

log_file = "ids_log.csv"

if not os.path.exists(log_file):
    with open(log_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp","src_ip","dst_ip","protocol","size","risk","status"])

# -----------------------------
# Packet processing function
# -----------------------------

def process_packet(packet):

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    size = len(packet)

    current_time = time.time()

    # -----------------------------
    # Initialize counters
    # -----------------------------

    if src_ip not in attack_counter:
        attack_counter[src_ip] = 0
        attack_start_time[src_ip] = current_time

    attack_counter[src_ip] += 1

    elapsed = current_time - attack_start_time[src_ip]

    if elapsed <= 0:
        elapsed = 1

    packet_rate = attack_counter[src_ip] / elapsed

    # -----------------------------
    # Detection logic
    # -----------------------------

    if packet_rate > 60:

        risk = "HIGH"
        status = "DOS ATTACK"

        print("\n⚠ DOS ATTACK DETECTED")
        print("SOURCE IP:", src_ip)
        print("PACKETS:", attack_counter[src_ip])
        print("RATE:", int(packet_rate), "pkts/sec")
        print("SUGGESTION: Block IP via firewall\n")

    elif packet_rate > 20:

        risk = "MEDIUM"
        status = "SUSPICIOUS"

    else:

        risk = "LOW"
        status = "NORMAL"

    # -----------------------------
    # Display packet info
    # -----------------------------

    print(f"{src_ip}\t{dst_ip}\t{proto}\t{size}\t{risk}\t{status}")

    # -----------------------------
    # Save to log file
    # -----------------------------
    # limit log file size
    if os.path.exists(log_file):

        with open(log_file) as f:
            lines = f.readlines()

        if len(lines) > MAX_LOG_LINES:
            with open(log_file, "w") as f:
                f.write(lines[0])  # keep header only


    # write event only if suspicious or attack
    if risk != "LOW":

        with open(log_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                time.time(),
                src_ip,
                dst_ip,
                proto,
                size,
                risk,
                status
            ])

# -----------------------------
# Start IDS
# -----------------------------

print("\nSRC IP\t\tDST IP\t\tPROTO\tSIZE\tRISK\tSTATUS")
print("-"*80)

print("Starting packet capture...\n")

sniff(prn=process_packet, store=False)