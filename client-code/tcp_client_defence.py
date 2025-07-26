#!/usr/bin/env python3
"""
TCP Client with Robust Defence Mechanism for MITM Window Size Zero Attack
"""

import socket
import time

def tcp_client_defence(server_ip="192.168.56.20", server_port=8080):
    """TCP client with robust defence against window size zero attack."""
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print(f"Connecting to {server_ip}:{server_port}...")
        client_socket.connect((server_ip, server_port))
        print("Connected successfully!")
        messages = [
            "Hello Server!",
            "This is a test message",
            "Testing TCP window scaling",
            "MITM Lab Test Data"
        ]
        timeout_count = 0
        total_sent = 0
        total_timeouts = 0
        for i, message in enumerate(messages, 1):
            print(f"Sending message {i}: {message}")
            client_socket.send(message.encode())
            total_sent += 1
            try:
                client_socket.settimeout(3)
                response = client_socket.recv(1024)
                print(f"Received response: {response.decode()}")
                timeout_count = 0  # Reset on success
            except socket.timeout:
                timeout_count += 1
                total_timeouts += 1
                print("No response received (timeout)")
                # If more than 30% of packets result in timeout, warn user
                if total_sent > 3 and total_timeouts / total_sent > 0.3:
                    print("CRITICAL: High rate of timeouts detected (>30%). Possible TCP window size zero attack!")
                    print("Attempting to reconnect...")
                    client_socket.close()
                    time.sleep(2)
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.connect((server_ip, server_port))
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
                    timeout_count = 0
            time.sleep(2)
        client_socket.close()
        print("Connection closed.")
    except socket.error as e:
        print(f"Socket error: {e}")
    except KeyboardInterrupt:
        print("\nClient interrupted by user")
        if 'client_socket' in locals():
            client_socket.close()

if __name__ == "__main__":
    tcp_client_defence()
