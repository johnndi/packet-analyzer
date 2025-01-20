import socket
import struct
import textwrap

TAb_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t  '             
DATA_TAB_2 = '\t\t  '
Data_TAB_3 = '\t\t\t  '
Data_TAB_4 = '\t\t\t\t  '   
def main():
    import pcap
    conn = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print( TAb_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:
            version, ihl, ttl, proto, src_ip, dest_ip, data = ip_packet(data)
            print(TAb_2 + 'IPv4:')
            print(TAB_3 + 'Version: {}, IHL: {}, TTL: {}, Protocol: {}'.format(version, ihl, ttl, proto))
            print(TAB_4 + 'Source: {}, Destination: {}'.format(src_ip, dest_ip))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_2 + 'ICMP Packet:')
                print(TAB_3 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_3 + 'Data:')
                print(format_multi_line(DATA_TAB_1, data))

            elif proto == 6:
                tcp_src_port, tcp_dest_port, seq, ack, flags, window_size, checksum, urg_ptr = struct.unpack('! H H L L H H H H', data[:20])
                print(TAB_2 + 'TCP Packet:')
                print(TAB_3 + 'Source Port: {}, Destination Port: {}, Sequence: {}, Acknowledgment: {}, Flags: {}, Window Size: {}, Checksum: {}, Urgent Pointer: {}'.format(tcp_src_port, tcp_dest_port, seq, ack, flags, window_size, checksum, urg_ptr))
                print(TAB_3 + 'Data:')
                print(format_multi_line(DATA_TAB_1, data[20:]))

            elif proto == 17:
                udp_src_port, udp_dest_port, length = struct.unpack('! H H H', data[:8])
                print(TAB_2 + 'UDP Packet:')
                print(TAB_3 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp_src_port, udp_dest_port, length))
                print(TAB_3 + 'Data:')
                print(format_multi_line(DATA_TAB_1, data[8:]))

            else:
                print(TAB_2 + 'Unknown Protocol: {}'.format(proto)) 


# unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

   # return properly formatted MAC address (AA:BB:CC:DD:EE:FF)
   # e.g. 00:1A:2B:3C:4D:5E
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# unpack IP ipv4 packets

def ip_packet(data):
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 15) *  4
    ttl, proto, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, ihl, ttl, proto, ipv4(src_ip), ipv4(dest_ip), data[ihl:]

    # return properly formatted IP address (XXX.XXX.XXX.XXX)
    # e.g. 192.168.0.1
def ipv4(addr):
    return '.'.join(map(str, addr))

    # unpack icmp/TCP/UDP packets
def icmp_packet(data):
    type, code, checksum, _ = struct.unpack('! B B H', data[:4])
    return type, code, checksum, data[4:]

    # unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, seq, ack, offset_reserved_flags) = struct.unpack('! H H L L H H H H', data[:20])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    return src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]  
    return src_port, dest_port, seq, ack, flag_urg, flag-ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]  


# unpack UDP packet
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# format multi-line data
def format_multi_line(prefix, string, size=80):
    size = len(prefix)  
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()