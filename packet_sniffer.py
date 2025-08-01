#!/usr/bin/env python3

import socket
import struct

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    src, target = struct.unpack('!4s4s', data[12:20])
    return socket.inet_ntoa(src), socket.inet_ntoa(target), data[header_length:]

def main():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("[*] Sniffing started... Press Ctrl+C to stop.")
    except PermissionError:
        print("[-] Run as root to sniff packets.")
        return

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f"\nEthernet Frame:")
        print(f"   > Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

        if eth_proto == 8:  # IPv4
            src_ip, dest_ip, _ = ipv4_packet(data)
            print(f"   > IPv4 Packet: {src_ip} -> {dest_ip}")

if __name__ == "__main__":
    main()
