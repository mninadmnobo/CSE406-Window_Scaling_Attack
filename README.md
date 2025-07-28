# MITM TCP Lab: Window Scaling Attack & ARP Poisoning


## Detailed Lab Process: ARP Poisoning, TCP Window Scaling Attack, and Defence



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
  sudo sysctl -w net.ipv4.ip_forward=1
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
  cd /media/sf_mitm-lab
  python3 tcp_client_defence.py
  ```

### Step 14: Stop/Close Terminals after Defence Client Run
- **Client VM (Terminal 3):** Stop/close after defence client finishes.
- **Attacker VM (Terminal 3, 4):** Stop/close after capture and analysis are complete.

---

### Wireshark Filters for Validation and Demonstration
**1. To see all traffic between client and server (for general inspection):**

```wireshark
ip.addr == 192.168.56.10 and ip.addr == 192.168.56.20 and tcp and !icmp
```
*Expected Behavior/Observation:* You can inspect all packets between the client and server. Under attack, you will notice increased delays, retransmissions, and possibly abrupt connection resets.
