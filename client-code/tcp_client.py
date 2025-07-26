#!/usr/bin/env python3
"""
TCP Client for MITM Lab Testing
"""

import socket
import time
import sys
from datetime import datetime

def tcp_client(server_ip="192.168.56.20", server_port=8080):
    """Simple TCP client to test connections."""
    
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
            "MITM Lab Test Data",
            # Add a very large message to simulate abrupt congestion under attack
            "BIG_MESSAGE: " + ("X" * 500000)  # 500KB payload
        ]
        
        for i, message in enumerate(messages, 1):
            now = datetime.now().strftime('%H:%M:%S')
            print(f"[{now}] Sending message {i} (len={len(message)}): ...")
            try:
                client_socket.sendall(message.encode())
                # Wait for response
                client_socket.settimeout(5)
                response = client_socket.recv(4096)
                now2 = datetime.now().strftime('%H:%M:%S')
                print(f"[{now2}] Received response: {response.decode()[:60]}... (truncated)")
            except socket.timeout:
                print(f"No response received (timeout) at {datetime.now().strftime('%H:%M:%S')}")
            except socket.error as e:
                print(f"Socket error during send/receive: {e}")
                break
            time.sleep(1)
        client_socket.close()
        print("Connection closed.")
        
    except socket.error as e:
        print(f"Socket error: {e}")
    except KeyboardInterrupt:
        print("\nClient interrupted by user")
        if 'client_socket' in locals():
            client_socket.close()

def continuous_client(server_ip="192.168.56.20", server_port=8080, interval=5):
    """Continuously connect and send data to test MITM attacks."""
    
    connection_count = 0
    
    while True:
        try:
            connection_count += 1
            print(f"\n=== Connection #{connection_count} ===")
            
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)  # 10 second timeout
            
            client_socket.connect((server_ip, server_port))
            print(f"Connected to {server_ip}:{server_port}")
        
            message = f"Connection #{connection_count} - {time.strftime('%H:%M:%S')}"
            client_socket.send(message.encode())
            
            response = client_socket.recv(1024)
            print(f"Server response: {response.decode()}")
            
            client_socket.close()
            print("Connection closed")
            
            time.sleep(interval)
            
        except socket.error as e:
            print(f"Connection error: {e}")
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopping continuous client...")
            break

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "continuous":
        continuous_client()
    else:
        tcp_client()
