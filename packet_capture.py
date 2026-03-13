from scapy.all import sniff, IP, TCP, UDP

# def capture_packets(packet_handler):

#     print("Starting packet capture...")

#     sniff(
#         prn=packet_handler,
#         store=False
#     )

def capture_packets(packet_handler):

    print("Starting packet capture...\n")

    sniff(
        prn=packet_handler,
        store=False
    )


def extract_packet_info(packet):

    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        pkt_len = len(packet)

        src_port = 0
        dst_port = 0

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_length": pkt_len
        }

    return None