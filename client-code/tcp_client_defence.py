#!/usr/bin/env python3
"""
TCP Client with Robust Defence Mechanism for MITM Window Size Zero Attack
"""

import socket
import time
from datetime import datetime

# More messages and larger payloads for robust testing
def generate_messages():
    base = "X" * 2048  # 2KB payload
    return [
        f"Message {i}: {base}" for i in range(1, 21)
    ]

def tcp_client_defence(server_ip="192.168.56.20", server_port=8080):
    """TCP client with robust defence against window size zero attack."""
    messages = generate_messages()
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print(f"Connecting to {server_ip}:{server_port}...")
    client_socket.connect((server_ip, server_port))
    print("Connected successfully!")
    total_sent = 0
    total_timeouts = 0
    timeout_count = 0
    reconnections = 0
    for i, message in enumerate(messages, 1):
        now = datetime.now().strftime('%H:%M:%S')
        print(f"[{now}] Sending message {i} (len={len(message)}): ...")
        client_socket.send(message.encode())
        total_sent += 1
        try:
            client_socket.settimeout(1.0)  # Lower timeout for demo
            response = client_socket.recv(4096)
            now2 = datetime.now().strftime('%H:%M:%S')
            print(f"[{now2}] Received response: {response.decode()[:60]}... (truncated)")
            timeout_count = 0  # Reset on success
        except socket.timeout:
            timeout_count += 1
            total_timeouts += 1
            print(f"No response received (timeout) at {datetime.now().strftime('%H:%M:%S')}")
            # If more than 30% of packets result in timeout, warn user
            if total_sent > 3 and total_timeouts / total_sent > 0.3:
                print("CRITICAL: High rate of timeouts detected (>30%). Possible TCP window size zero attack!")
                print("Attempting to reconnect...")
                client_socket.close()
                time.sleep(2)
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((server_ip, server_port))
                reconnections += 1
                timeout_count = 0
                total_timeouts = 0
                total_sent = 0
            # If 3 consecutive timeouts, also warn and reconnect
            elif timeout_count >= 3:
                print("WARNING: Multiple consecutive timeouts. Possible TCP window size zero attack!")
                print("Attempting to reconnect...")
                client_socket.close()
                time.sleep(2)
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((server_ip, server_port))
                reconnections += 1
                timeout_count = 0
        time.sleep(0.5)
    client_socket.close()
    print(f"\nSummary: Sent={total_sent}, Timeouts={total_timeouts}, Reconnections={reconnections}")

if __name__ == "__main__":
    tcp_client_defence()
