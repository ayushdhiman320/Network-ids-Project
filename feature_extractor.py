import time
from collections import defaultdict
import numpy as np

FLOW_TIMEOUT = 10

flows = defaultdict(list)


def update_flow(packet):

    flow_key = (
        packet["src_ip"],
        packet["dst_ip"],
        packet["src_port"],
        packet["dst_port"],
        packet["protocol"]
    )

    flows[flow_key].append({
        "size": packet["packet_length"],
        "time": time.time(),
        "src": packet["src_ip"],
        "dst": packet["dst_ip"]
    })

    return flow_key


def compute_flow_features(flow_key):

    packets = flows[flow_key]

    now = time.time()

    packets = [p for p in packets if now - p["time"] < FLOW_TIMEOUT]

    flows[flow_key] = packets

    if len(packets) < 2:
        return None

    sizes = [p["size"] for p in packets]

    times = [p["time"] for p in packets]

    src_ip = flow_key[0]

    dst_ip = flow_key[1]

    duration = max(times) - min(times)

    if duration == 0:
        duration = 1

    total_packets = len(sizes)

    total_bytes = sum(sizes)

    packets_per_sec = total_packets / duration

    bytes_per_sec = total_bytes / duration

    mean_size = np.mean(sizes)

    std_size = np.std(sizes)

    max_size = max(sizes)

    min_size = min(sizes)

    return {

        "Destination Port": flow_key[3],

        "Flow Duration": duration,

        "Total Packets": total_packets,

        "Total Bytes": total_bytes,

        "Packets/s": packets_per_sec,

        "Bytes/s": bytes_per_sec,

        "Average Packet Size": mean_size,

        "Packet Length Std": std_size,

        "Max Packet Length": max_size,

        "Min Packet Length": min_size,

        "Subflow Bwd Bytes": total_bytes,

        "Bwd Packets/s": packets_per_sec,

        "Bwd Packet Length Mean": mean_size,

        "Total Length of Bwd Packets": total_bytes

    }