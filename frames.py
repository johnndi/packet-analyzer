import socket
import struct
import textwrap
import tkinter as tk
from tkinter import scrolledtext
import threading

# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack IP IPv4 packets
def ip_packet(data):
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 15) * 4
    ttl, proto, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, ihl, ttl, proto, ipv4(src_ip), ipv4(dest_ip), data[ihl:]

# Return properly formatted IP address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Format multi-line data
def format_multi_line(prefix, string, size=80):
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Start sniffer and update text box
def start_sniffer(text_box):
    print('Sniffer started!')
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        conn.bind(('wlan0', 0))
        text_box.insert(tk.END, 'Listening on interface wlan0...\n')
    except Exception as e:
        text_box.insert(tk.END, f'Error creating socket: {e}\n')
        return

    while True:
        try:
            raw_data, _ = conn.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            packet_info = f'\nEthernet Frame:\nDestination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}\n'

            if eth_proto == 8:
                version, ihl, ttl, proto, src_ip, dest_ip, data = ip_packet(data)
                packet_info += f'IPv4 Packet:\nVersion: {version}, IHL: {ihl}, TTL: {ttl}, Protocol: {proto}\n'
                packet_info += f'Source: {src_ip}, Destination: {dest_ip}\n'

            text_box.insert(tk.END, packet_info)
            text_box.see(tk.END)
        except Exception as e:
            text_box.insert(tk.END, f'Error receiving packet: {e}\n')

# Start sniffer in a separate thread
def start_sniffer_thread(text_box):
    thread = threading.Thread(target=start_sniffer, args=(text_box,), daemon=True)
    thread.start()

# Create the GUI
def create_gui():
    root = tk.Tk()
    root.title('Network Sniffer')
    root.geometry('600x400')

    text_box = scrolledtext.ScrolledText(root, wrap=tk.WORD)
    text_box.pack(expand=True, fill='both')

    text_box.insert(tk.END, 'Testing text box...\n')
    start_sniffer_thread(text_box)
    root.mainloop()

if __name__ == '__main__':
    create_gui()
