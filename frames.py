import socket
import struct
import textwrap

# unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

   # return properly formatted MAC address (AA:BB:CC:DD:EE:FF)
   # e.g. 00:1A:2B:3C:4D:5E
   def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()
      