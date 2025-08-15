import socket
import struct
import os
import ctypes
print("Admin rights:", ctypes.windll.shell32.IsUserAnAdmin())
# SCAPY TEST BLOCK – Run once at start to verify Scapy works
try:
    from scapy.all import sniff

    def test_scapy(packet):
        print("Scapy is working! Example Packet:", packet.summary())
        raise KeyboardInterrupt  # Stop sniffing after one packet

    print(" Verifying Scapy installation...")
    sniff(count=1, prn=test_scapy, store=False)
except ImportError:
    print("Scapy is not installed. Please run: pip install scapy")
    exit()
except Exception as e:
    print("Scapy test complete.\n")

# Raw socket-based sniffer (Windows-compatible)

# Convert 4-byte IP to human-readable format
def ipv4(addr):
    return '.'.join(map(str, addr))

# Parse the IP header
def parse_ip_header(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    ihl = (version_header_len & 0xF) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return version, ihl, ttl, proto, ipv4(src), ipv4(target), data[ihl:]

# Parse TCP segment
def parse_tcp_segment(data):
    src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dst_port, seq, ack, data[offset:]

# Parse UDP segment
def parse_udp_segment(data):
    src_port, dst_port, length = struct.unpack('!HHH', data[:6])
    return src_port, dst_port, data[8:]

# Parse ICMP packet
def parse_icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return icmp_type, code, data[4:]

def start_sniffer():
    # Get local IP address
    host = socket.gethostbyname(socket.gethostname())

    # Create raw socket for Windows IP-level sniffing
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind((host, 0))

    # Include IP headers in captured packets
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode on Windows
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"\n Raw Socket Sniffer Running on {host} (Windows) — Press Ctrl+C to stop")

    try:
        while True:
            raw_data, addr = sock.recvfrom(65535)
            version, ihl, ttl, proto, src_ip, dst_ip, ip_payload = parse_ip_header(raw_data)

            print(f"\n IPv4 Packet: {src_ip} → {dst_ip}, Protocol: {proto}, TTL: {ttl}")

            if proto == 6:  # TCP
                src_port, dst_port, seq, ack, tcp_data = parse_tcp_segment(ip_payload)
                print(f" TCP: {src_ip}:{src_port} → {dst_ip}:{dst_port}, Seq={seq}, Ack={ack}")
            elif proto == 17:  # UDP
                src_port, dst_port, udp_data = parse_udp_segment(ip_payload)
                print(f" UDP: {src_ip}:{src_port} → {dst_ip}:{dst_port}, Length={len(udp_data)}")
            elif proto == 1:  # ICMP
                icmp_type, code, icmp_data = parse_icmp_packet(ip_payload)
                print(f" ICMP: Type={icmp_type}, Code={code}, Length={len(icmp_data)}")

    except KeyboardInterrupt:
        # Turn off promiscuous mode before exiting
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("\n Raw Socket Sniffer stopped.")

if __name__ == '__main__':
    start_sniffer()
