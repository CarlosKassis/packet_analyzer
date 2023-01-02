from scapy.all import *
from scapy import *
import ipaddress

ips = set()
ip_to_hostname = dict()
interactions = set()

def try_get_ip_hostname_info(packet):
    if not DNS in packet or not packet.qr == 1:
        return

    try:
        for i in range(packet.ancount):
            dnsrr = packet.an[i]
            if not dnsrr.type == 1: # AAAA
                continue

            hostname = str(dnsrr.rrname, 'utf8')
            ip = dnsrr.rdata

            ip_to_hostname[ip] = hostname
    except:
        pass

def black_listed_ip(ip):
    hardcoded_blacklisted_ips = { "0.0.0.0", "255.255.255.255",}

    if ip in hardcoded_blacklisted_ips:
        return True

    if str.startswith(ip, "224.0.0."):
        return True

    return False

def try_add_distinct_node_ip(packet):
    if not IP in packet:
        return

    if not black_listed_ip(packet[IP].src):
        ips.add(packet[IP].src)
    if not black_listed_ip(packet[IP].dst):
        ips.add(packet[IP].dst)

def try_add_interaction(packet):
    if not IP in packet:
        return

    ip1 = packet[IP].src
    ip2 = packet[IP].dst

    if black_listed_ip(ip1) or black_listed_ip(ip2):
        return

    interactions.add(( ip1, ip2 ) if ipaddress.ip_address(ip1) < ipaddress.ip_address(ip2) else ( ip2, ip1 ))

def analyze(pcap_path):
    scapy_pcap = PcapReader(pcap_path)

    for packet in scapy_pcap:
        try_add_distinct_node_ip(packet)
        try_get_ip_hostname_info(packet)
        try_add_interaction(packet)

    info = dict()

    entity_info = dict()
    for ip in ips:
        entity_info[ip] = {"hostname" : None if ip not in ip_to_hostname else ip_to_hostname[ip]}
    
    info["entities"] = entity_info
    info["interactions"] = interactions

    return dict(info)