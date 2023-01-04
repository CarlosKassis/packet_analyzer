from scapy.all import *
from scapy import *
import ipaddress

class PacketAnalyzer:
    def __init__(self, capture_file_path):
        self.capture_file_path = capture_file_path
        self.ips = set()
        self.ip_to_hostname = dict()
        self.interactions = set()
        self.open_ports = set()

    def try_get_ip_hostname_info(self, packet):
        if not DNS in packet or not packet.qr == 1:
            return

        try:
            for i in range(packet.ancount):
                dnsrr = packet.an[i]
                if not dnsrr.type == 1: # AAAA
                    continue

                hostname = str(dnsrr.rrname, 'utf8')
                ip = dnsrr.rdata

                self.ip_to_hostname[ip] = hostname
        except:
            pass

    def black_listed_ip(self, ip):
        hardcoded_blacklisted_ips = { "0.0.0.0", "255.255.255.255",}

        if ip in hardcoded_blacklisted_ips:
            return True

        if str.startswith(ip, "224.0.0."):
            return True

        return False

    def try_add_distinct_node_ip(self, packet):
        if not IP in packet:
            return

        if not self.black_listed_ip(packet[IP].src):
            self.ips.add(packet[IP].src)
        if not self.black_listed_ip(packet[IP].dst):
            self.ips.add(packet[IP].dst)

    def try_add_interaction(self, packet):
        if not IP in packet:
            return

        ip1 = packet[IP].src
        ip2 = packet[IP].dst

        if self.black_listed_ip(ip1) or self.black_listed_ip(ip2):
            return

        self.interactions.add(( ip1, ip2 ) if ipaddress.ip_address(ip1) < ipaddress.ip_address(ip2) else ( ip2, ip1 ))

    def try_add_open_service_port(self, packet):
        if not TCP in packet and not UDP in packet:
            return
        
        # check ack flag
        if TCP in packet and packet[TCP].flags & 16 != 16:
            return

        port = packet[TCP].sport if TCP in packet else packet[UDP].sport
        # TODO: better criterea?
        if port >= 1024:
            return

        self.open_ports.add(("TCP" if TCP in packet else "UDP", port))
        
    def analyze(self):
        try:
            packets = PcapReader(self.capture_file_path)
        except:
            return "Invalid capture file"

        for packet in packets:
            self.try_add_distinct_node_ip(packet)
            self.try_get_ip_hostname_info(packet)
            self.try_add_interaction(packet)
            self.try_add_open_service_port(packet)
        
        info = dict()

        entity_info = dict()
        for ip in self.ips:
            entity_info[ip] = {"hostname" : None if ip not in self.ip_to_hostname else self.ip_to_hostname[ip]}
        
        info["entities"] = entity_info
        info["interactions"] = self.interactions
        info["open_ports"] = list(self.open_ports)

        return dict(info)
