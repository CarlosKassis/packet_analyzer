from scapy.all import *
from scapy import *
import ipaddress
from scapy.layers.http import HTTP, HTTPRequest
import time

GUESSED_SUBNET_MASK = '255.255.255.0'

class PacketAnalyzer:
    def __init__(self, capture_file_path):
        self.capture_file_path = capture_file_path

        self.ips = set()
        self.ip_to_hostname = dict()
        self.ip_to_services = dict()
        self.ip_to_os = dict()
        self.ip_to_mac = dict()

        self.interactions = set()

        self.real_subnet_to_info = dict()
        self.guessed_subnets = set()

    # Use DNS to get hostname associated with IP
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


    # Check source and destination IP
    def try_add_distinct_node_ip(self, packet):
        if not IP in packet:
            return

        if not self.black_listed_ip(packet[IP].src):
            self.ips.add(ipaddress.ip_address(packet[IP].src))
        if not self.black_listed_ip(packet[IP].dst):
            self.ips.add(ipaddress.ip_address(packet[IP].dst))


    # Check source and destination IP
    def try_get_interaction(self, packet):
        if not IP in packet:
            return

        if self.black_listed_ip(packet[IP].src) or self.black_listed_ip(packet[IP].dst):
            return

        ip1 = ipaddress.ip_address(packet[IP].src)
        ip2 = ipaddress.ip_address(packet[IP].dst)

        self.interactions.add(( ip1, ip2 ) if ip1 < ip2 else ( ip2, ip1))

    # Check used ports for TCP/UDP
    def try_get_open_service_port(self, packet):
        if (not TCP in packet and not UDP in packet) or not IP in packet:
            return
        
        # check ack flag
        if TCP in packet and packet[TCP].flags & 16 != 16:
            return

        port = packet[TCP].sport if TCP in packet else packet[UDP].sport
        # TODO: better criterea?
        if port >= 1024:
            return

        source_ip = packet[IP].src
        if not source_ip in self.ip_to_services:
             self.ip_to_services[source_ip] = set()

        (self.ip_to_services[source_ip]).add(("TCP" if TCP in packet else "UDP", port))


    # Use DHCP to get real subnet info
    def try_get_real_subnet_info(self, packet):
        if not DHCP in packet:
            return
        
        BOOTP_REPLY = 2
        if packet[BOOTP].op != BOOTP_REPLY:
            return

        gateway = None
        subnet_mask = None
        for option in packet[DHCP].options:
            if option[0] == "router":
                gateway = option[1]
            elif option[0] == "subnet_mask":
                subnet_mask = option[1]

        if gateway == None or subnet_mask == None:
            return
        
        self.real_subnet_to_info[ipaddress.ip_network(f'{gateway}/{subnet_mask}', strict=False)] = { "gateway": gateway, "type": "real", "entities": []}

    # Use DHCP to get real subnet info
    def try_guess_subnet_info(self, packet):
        if not IP in packet:
            return
        
        self.guessed_subnets.add(ipaddress.ip_network(f'{packet[IP].src}/{GUESSED_SUBNET_MASK}', strict=False))
        self.guessed_subnets.add(ipaddress.ip_network(f'{packet[IP].dst}/{GUESSED_SUBNET_MASK}', strict=False))

    def try_get_mac_info(self, packet):
        if not ARP in packet:
            return

        if packet[ARP].op != 2: # ARP is-at
            return
        
        self.ip_to_mac[str(packet[ARP].psrc)] = str(packet[ARP].hwsrc)

    def get_guessed_subnet_for_ip(self, ip):
        return ipaddress.ip_network(f'{ip}/{GUESSED_SUBNET_MASK}' if ip not in self.ip_to_subnet else self.ip_to_subnet[ip], strict=False)


    def analyze(self):
        curr_time = time.time()
        try:
            packets = PcapReader(self.capture_file_path)
        except:
            return "Invalid capture file"

        for packet in packets:
            self.try_add_distinct_node_ip(packet)
            self.try_get_ip_hostname_info(packet)
            self.try_get_interaction(packet)
            self.try_get_open_service_port(packet)
            self.try_get_real_subnet_info(packet)
            self.try_guess_subnet_info(packet)
            self.try_get_mac_info(packet)

        info = dict()

        entities = dict()
        guessed_subnet_to_info = dict()
        for ip in self.ips:
            entity_info = dict()
            entity_info["mac"] = "Unknown" if ip not in self.ip_to_mac else self.ip_to_mac[ip]
            entity_info["hostname"] = None if ip not in self.ip_to_hostname else self.ip_to_hostname[ip]
            entity_info["services"] = list() if ip not in self.ip_to_services else list(self.ip_to_services[ip])
            entity_info["os"] = "Unknown" if ip not in self.ip_to_os else self.ip_to_os[ip]

            found_subnet_for_ip = False
            for subnet in self.real_subnet_to_info:
                if ip not in subnet:
                    continue

                subnet_data = self.real_subnet_to_info[subnet]

                subnet_data["entities"].append(ip)
                entity_info["subnet"] = str(subnet)
                found_subnet_for_ip = True
                break
            
            if not found_subnet_for_ip:
                guessed_subnet_for_ip = ipaddress.ip_network(f'{str(ip)}/{GUESSED_SUBNET_MASK}', strict=False)
                if not ip in guessed_subnet_for_ip:
                    print(f"Weird, no subnet found for {ip}")
                    continue

                if guessed_subnet_for_ip not in guessed_subnet_to_info:
                    guessed_subnet_to_info[guessed_subnet_for_ip] = { "type": "guessed", "entities": []}

                (guessed_subnet_to_info[guessed_subnet_for_ip]["entities"]).append(str(ip))
                entity_info["subnet"] = str(guessed_subnet_for_ip)
            
            entities[str(ip)] = entity_info
        
        info["entities"] = entities
        info["interactions"] = [(str(ip1), str(ip2)) for (ip1, ip2) in self.interactions]
        
        subnets = dict()
        for subnet in guessed_subnet_to_info:
            subnets[str(subnet)] = guessed_subnet_to_info[subnet]

        info["subnets"] = subnets

        print(f'time took to process file: {time.time() - curr_time}')

        return dict(info)
