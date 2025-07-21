#!/usr/bin/env python3
"""
TCP Server for MITM Lab Testing
"""

import socket
import threading
import time
import sys

def handle_client(client_socket, client_address):
    """Handle individual client connections."""
    
    try:
        print(f"New client connected: {client_address}")
        
        while True:
            # Receive data from client
            data = client_socket.recv(1024)
            if not data:
                break
                
            message = data.decode()
            print(f"Received from {client_address}: {message}")
            
            # Send response back to client
            response = f"Server received: {message} at {time.strftime('%H:%M:%S')}"
            client_socket.send(response.encode())
            
    except socket.error as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"Client {client_address} disconnected")

def tcp_server(host="0.0.0.0", port=8080):
    """TCP Server to receive connections from clients."""
    
    try:
        # Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind to address and port
        server_socket.bind((host, port))
        server_socket.listen(5)
        
        print(f"TCP Server listening on {host}:{port}")
        print("Waiting for client connections...")
        
        while True:
            # Accept client connections
            client_socket, client_address = server_socket.accept()
            
            # Handle each client in a separate thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True
            )
            client_thread.start()
            
    except socket.error as e:
        print(f"Server error: {e}")
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        if 'server_socket' in locals():
            server_socket.close()

def simple_echo_server(host="0.0.0.0", port=8080):
    """Simple echo server for basic testing."""
    
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(1)
        
        print(f"Echo Server listening on {host}:{port}")
        
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Connection from {client_address}")
            
            try:
                while True:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    # Echo data back
                    client_socket.send(data)
                    print(f"Echoed: {data.decode()}")
                    
            except socket.error:
                pass
            finally:
                client_socket.close()
                print(f"Connection from {client_address} closed")
                
    except KeyboardInterrupt:
        print("\nEcho server shutting down...")
    finally:
        if 'server_socket' in locals():
            server_socket.close()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "echo":
        simple_echo_server()
    else:
        tcp_server()
