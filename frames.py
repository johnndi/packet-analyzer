import socket
import struct
import textwrap
import tkinter as tk
from tkinter import scrolledtext, ttk
import threading

LOG_FILE = "sniffer_logs.txt"

def save_log(message):
    with open(LOG_FILE, "a") as file:
        file.write(message + "\n")

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
def start_sniffer(sniffer_text_box, log_text_box):
    print('Sniffer started!')
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        conn.bind(('wlan0', 0))
        sniffer_text_box.insert(tk.END, 'Listening on interface wlan0...\n')
        log_text_box.insert(tk.END, 'Sniffer started successfully.\n')
        save_log('Sniffer started successfully.')
    except Exception as e:
        error_msg = f'Error creating socket: {e}\n'
        sniffer_text_box.insert(tk.END, error_msg)
        log_text_box.insert(tk.END, error_msg)
        save_log(error_msg)
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

            sniffer_text_box.insert(tk.END, packet_info)
            sniffer_text_box.see(tk.END)
            log_entry = f'Packet captured: {src_ip} -> {dest_ip}'
            log_text_box.insert(tk.END, log_entry + "\n")
            log_text_box.see(tk.END)
            save_log(log_entry)
        except Exception as e:
            error_msg = f'Error receiving packet: {e}\n'
            sniffer_text_box.insert(tk.END, error_msg)
            log_text_box.insert(tk.END, error_msg)
            save_log(error_msg)

# Start sniffer in a separate thread
def start_sniffer_thread(sniffer_text_box, log_text_box):
    thread = threading.Thread(target=start_sniffer, args=(sniffer_text_box, log_text_box), daemon=True)
    thread.start()

# Create the GUI
def create_gui():
    root = tk.Tk()
    root.title('Network Sniffer')
    root.geometry('600x400')

    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill='both')

    sniffer_frame = ttk.Frame(notebook)
    log_frame = ttk.Frame(notebook)

    notebook.add(sniffer_frame, text='Sniffer')
    notebook.add(log_frame, text='Logs')

    sniffer_text_box = scrolledtext.ScrolledText(sniffer_frame, wrap=tk.WORD)
    sniffer_text_box.pack(expand=True, fill='both')

    log_text_box = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
    log_text_box.pack(expand=True, fill='both')

    sniffer_text_box.insert(tk.END, 'Testing sniffer text box...\n')
    log_text_box.insert(tk.END, 'Testing log text box...\n')
    save_log('Testing log text box...')

    start_sniffer_thread(sniffer_text_box, log_text_box)
    root.mainloop()

if __name__ == '__main__':
    create_gui()
