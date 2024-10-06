#!/usr/bin/env python3

import argparse
from scapy.all import *
import os
import logging

# Configurar logging para mensajes de errores e información
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Funcion para procesar los paquetes capturados
def process_packet(packet):
    try:
        print("\n[+] New Packet Captured:")

        # Capa Ethernet (direcciones MAC)
        if packet.haslayer(Ether):
            eth_src = packet[Ether].src
            eth_dst = packet[Ether].dst
            eth_type = packet[Ether].type
            print(f"    [Ethernet] {eth_src} -> {eth_dst} | Type: {hex(eth_type)}")

        # Capa IP (soporta tanto IPv4 como IPv6)
        if packet.haslayer(IP) or packet.haslayer(IPv6):
            if packet.haslayer(IP):
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                ttl = packet[IP].ttl
                proto = packet[IP].proto
                print(f"    [IPv4] {ip_src} -> {ip_dst} | TTL: {ttl} | Protocol: {proto}")

            elif packet.haslayer(IPv6):
                ip_src = packet[IPv6].src
                ip_dst = packet[IPv6].dst
                hlim = packet[IPv6].hlim
                proto = packet[IPv6].nh
                print(f"    [IPv6] {ip_src} -> {ip_dst} | HLIM: {hlim} | Next Header: {proto}")
            
            # Capa TCP
            if packet.haslayer(TCP):
                tcp_src_port = packet[TCP].sport
                tcp_dst_port = packet[TCP].dport
                seq = packet[TCP].seq
                ack = packet[TCP].ack
                flags = packet[TCP].flags
                print(f"    [TCP] {ip_src}:{tcp_src_port} -> {ip_dst}:{tcp_dst_port} | Seq: {seq}, Ack: {ack}, Flags: {flags}")

            # Capa UDP
            elif packet.haslayer(UDP):
                udp_src_port = packet[UDP].sport
                udp_dst_port = packet[UDP].dport
                length = packet[UDP].len
                print(f"    [UDP] {ip_src}:{udp_src_port} -> {ip_dst}:{udp_dst_port} | Length: {length}")

            # Capa ICMP
            elif packet.haslayer(ICMP) or packet.haslayer(ICMPv6EchoRequest):
                if packet.haslayer(ICMP):
                    icmp_type = packet[ICMP].type
                    icmp_code = packet[ICMP].code
                    print(f"    [ICMP] {ip_src} -> {ip_dst} | Type: {icmp_type}, Code: {icmp_code}")
                elif packet.haslayer(ICMPv6EchoRequest):
                    icmpv6_type = packet[ICMPv6EchoRequest].type
                    print(f"    [ICMPv6] {ip_src} -> {ip_dst} | Type: {icmpv6_type}")

        # Capa ARP
        if packet.haslayer(ARP):
            arp_op = packet[ARP].op
            arp_src_ip = packet[ARP].psrc
            arp_dst_ip = packet[ARP].pdst
            print(f"    [ARP] {arp_src_ip} -> {arp_dst_ip} | Operation: {arp_op}")

        # Capa DNS
        if packet.haslayer(DNS):
            dns_query = packet[DNS].qd.qname if packet[DNS].qd else b"Unknown"
            print(f"    [DNS] Query: {dns_query.decode('utf-8', 'ignore')}")
        
        # Mostrar el payload crudo (datos)
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            print(f"    [Raw] Payload: {raw_data[:100]}...")  # Mostrar los primeros 100 bytes del payload

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

# Función principal para iniciar el sniffing
def start_sniffing(interface, bpf_filter, packet_count):
    # Verificar si el script se está ejecutando como root
    if not os.geteuid() == 0:
        logging.error("[!] Please run this script as root (or with sudo) to capture packets.")
        return
    
    try:
        logging.info(f"[*] Starting packet capture on interface: {interface} with filter: '{bpf_filter}'")
        sniff(iface=interface, filter=bpf_filter, prn=process_packet, count=packet_count, store=False)
    except Scapy_Exception as e:
        logging.error(f"Error occurred during packet capture: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="NetSnoopSpoof: Comprehensive network packet sniffer using Scapy")
    
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter for sniffing (optional, e.g., 'tcp', 'udp', 'icmp')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 means unlimited)")

    args = parser.parse_args()

    # Start packet sniffing
    start_sniffing(args.interface, args.filter, args.count)
