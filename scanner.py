import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP
# import scapy.all. as Ether

import logging
import socket


interface = None
# Packet list of open hosts
open_hosts = []


def arp_scan():
    print('')
    try:
        interface = input('[*] Enter interface to scan on: ')
        net_addr = input('[*] Enter network address with net mask: ')
        print('[*] Scanning...')
        ans,unans = scapy.srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=net_addr), iface=interface, \
                              timeout=2, inter=0.1)
        print(ans)
        ans.display()
        print(unans)
        print('MAC - IP')
        for send, recv in ans:
            print(recv[Ether].src+' - '+recv[ARP].psrc)
            open_hosts.append(recv)
        print('[*] Scan complete')
        print('Result')
    except KeyboardInterrupt:
        print()
        print('[*] Quitting')


def port_scan():
    print('')
    try:
        for host in open_hosts:
            dst_ip = str(host[ARP].psrc)
            src_port = 50
            dst_port = 1883
            response = scapy.sr1(IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='S'), timeout=10)
            if str(type(response)) == '<class \'NoneType\'>':
                print('Syn Request filtered')
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:
                    scapy.sr(IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='R'), timeout=10)
                    print('Host '+dst_ip+' has port '+str(dst_port)+' open')
                elif response.getlayer(TCP).flags == 0x14:
                    print('Host '+dst_ip+' has port '+str(dst_port)+' closed')

    except KeyboardInterrupt:
        print()
        print('[*] Quitting')
