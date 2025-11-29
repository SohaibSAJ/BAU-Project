import csv
import json
import ipaddress
from scapy.all import sniff, get_if_list, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ARP, DNS, DNSQR, DNSRR, Raw
import os
from datetime import datetime, timedelta
import signal
import threading

# --- Create logs folder inside script's directory ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(SCRIPT_DIR, 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)
print(f"Logs folder created at {LOGS_DIR}")

# --- Generate new file paths ---
def generate_file_paths():
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    txt_file = os.path.join(LOGS_DIR, f'packets_{timestamp}.txt')
    csv_file = os.path.join(LOGS_DIR, f'packets_{timestamp}.csv')
    json_file = os.path.join(LOGS_DIR, f'packets_{timestamp}.json')
    return txt_file, csv_file, json_file

# --- TCP Flags Decoder ---
def decode_tcp_flags(flag_value):
    """Convert TCP flag integer to readable flags list."""
    flags = []
    if flag_value & 1:
        flags.append("FIN")
    if flag_value & 2:
        flags.append("SYN")
    if flag_value & 4:
        flags.append("RST")
    if flag_value & 8:
        flags.append("PSH")
    if flag_value & 16:
        flags.append("ACK")
    if flag_value & 32:
        flags.append("URG")
    if flag_value & 64:
        flags.append("ECE")
    if flag_value & 128:
        flags.append("CWR")
    return ",".join(flags)

# --- Packet Summary Function ---
def packet_summary(pkt, interface):
    summary = {
        'timestamp': pkt.time,
        'interface': interface,
        'src_ip': None,
        'dst_ip': None,
        'protocol': None,
        'length': len(pkt),
        'src_port': None,
        'dst_port': None,
        'tcp_flags': None,
        'tcp_syn': None,
        'tcp_ack': None,
        'tcp_fin': None,
        'tcp_rst': None,
        'tcp_psh': None,
        'seq': None,
        'ack': None,
        'icmp_type': None,
        'icmp_code': None,
        'arp_op': None,
        'arp_psrc': None,
        'arp_pdst': None,
        'arp_hwsrc': None,
        'arp_hwdst': None,
        'dns_query': None,
        'dns_qname': None,
        'dns_qtype': None,
        'dns_response': None,
        'dns_answer_count': None,
        'dns_answer_size': None,
        'http_method': None,
        'http_path': None,
        'http_status_code': None,
        'http_host': None
    }

    # IPv4
    if IP in pkt:
        summary['src_ip'] = pkt[IP].src
        summary['dst_ip'] = pkt[IP].dst
        if TCP in pkt:
            tcp = pkt[TCP]
            summary['protocol'] = 'TCP'
            summary['src_port'] = tcp.sport
            summary['dst_port'] = tcp.dport
            summary['tcp_flags'] = decode_tcp_flags(tcp.flags.value)
            summary['seq'] = tcp.seq
            summary['ack'] = tcp.ack
            
            # Individual TCP flag booleans for ML features
            summary['tcp_syn'] = bool(tcp.flags.value & 0x02)
            summary['tcp_ack'] = bool(tcp.flags.value & 0x10)
            summary['tcp_fin'] = bool(tcp.flags.value & 0x01)
            summary['tcp_rst'] = bool(tcp.flags.value & 0x04)
            summary['tcp_psh'] = bool(tcp.flags.value & 0x08)
            
            # HTTP detection (common ports: 80, 443, 8080, etc.)
            if Raw in pkt and tcp.dport in [80, 8080, 8000, 3000]:
                payload = bytes(pkt[Raw].load)
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    lines = payload_str.split('\r\n')
                    if lines:
                        first_line = lines[0].split()
                        # HTTP Request
                        if len(first_line) >= 2 and first_line[0] in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']:
                            summary['http_method'] = first_line[0]
                            summary['http_path'] = first_line[1] if len(first_line) > 1 else None
                            # Extract Host header
                            for line in lines[1:]:
                                if line.lower().startswith('host:'):
                                    summary['http_host'] = line.split(':', 1)[1].strip()
                                    break
                        # HTTP Response
                        elif first_line[0].startswith('HTTP/'):
                            if len(first_line) >= 2:
                                summary['http_status_code'] = first_line[1]
                except:
                    pass
                    
        elif UDP in pkt:
            udp = pkt[UDP]
            summary['protocol'] = 'UDP'
            summary['src_port'] = udp.sport
            summary['dst_port'] = udp.dport
            
            # DNS detection (port 53)
            if DNS in pkt:
                dns = pkt[DNS]
                summary['dns_query'] = dns.qr == 0  # 0 = query, 1 = response
                summary['dns_response'] = dns.qr == 1
                
                # DNS Query fields
                if DNSQR in pkt:
                    try:
                        summary['dns_qname'] = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                        summary['dns_qtype'] = pkt[DNSQR].qtype
                    except:
                        pass
                
                # DNS Response fields
                if dns.qr == 1 and dns.an:
                    summary['dns_answer_count'] = dns.ancount
                    # Calculate total answer size
                    answer_size = 0
                    try:
                        rr = dns.an
                        while rr:
                            if hasattr(rr, 'rdata'):
                                answer_size += len(str(rr.rdata))
                            rr = rr.payload if hasattr(rr, 'payload') else None
                        summary['dns_answer_size'] = answer_size
                    except:
                        pass
                        
        elif ICMP in pkt:
            icmp = pkt[ICMP]
            summary['protocol'] = 'ICMP'
            summary['icmp_type'] = icmp.type
            summary['icmp_code'] = icmp.code
        else:
            summary['protocol'] = 'OTHER'

    # IPv6
    elif IPv6 in pkt:
        summary['src_ip'] = pkt[IPv6].src
        summary['dst_ip'] = pkt[IPv6].dst
        if TCP in pkt:
            tcp = pkt[TCP]
            summary['protocol'] = 'TCP'
            summary['src_port'] = tcp.sport
            summary['dst_port'] = tcp.dport
            summary['tcp_flags'] = decode_tcp_flags(tcp.flags.value)
            summary['seq'] = tcp.seq
            summary['ack'] = tcp.ack
            
            # Individual TCP flag booleans
            summary['tcp_syn'] = bool(tcp.flags.value & 0x02)
            summary['tcp_ack'] = bool(tcp.flags.value & 0x10)
            summary['tcp_fin'] = bool(tcp.flags.value & 0x01)
            summary['tcp_rst'] = bool(tcp.flags.value & 0x04)
            summary['tcp_psh'] = bool(tcp.flags.value & 0x08)
            
        elif UDP in pkt:
            udp = pkt[UDP]
            summary['protocol'] = 'UDP'
            summary['src_port'] = udp.sport
            summary['dst_port'] = udp.dport
            
            # DNS detection
            if DNS in pkt:
                dns = pkt[DNS]
                summary['dns_query'] = dns.qr == 0
                summary['dns_response'] = dns.qr == 1
                if DNSQR in pkt:
                    try:
                        summary['dns_qname'] = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                        summary['dns_qtype'] = pkt[DNSQR].qtype
                    except:
                        pass
                if dns.qr == 1 and dns.an:
                    summary['dns_answer_count'] = dns.ancount
                    
        elif ICMPv6EchoRequest in pkt:
            icmpv6 = pkt[ICMPv6EchoRequest]
            summary['protocol'] = 'ICMPv6'
            summary['icmp_type'] = icmpv6.type
            summary['icmp_code'] = icmpv6.code
        else:
            summary['protocol'] = 'OTHER'

    # ARP
    elif ARP in pkt:
        arp = pkt[ARP]
        summary['protocol'] = 'ARP'
        summary['arp_op'] = arp.op  # 1=request, 2=reply
        summary['arp_psrc'] = arp.psrc
        summary['arp_pdst'] = arp.pdst
        summary['arp_hwsrc'] = arp.hwsrc
        summary['arp_hwdst'] = arp.hwdst

    else:
        summary['protocol'] = 'OTHER'

    return summary

# --- Write Functions ---
def write_txt(packets, txt_file):
    with open(txt_file, 'w') as f:
        for p in packets:
            f.write(str(p) + '\n')
    print(f"Wrote {len(packets)} packets to {txt_file}")

def write_csv(packets, csv_file):
    with open(csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=packets[0].keys())
        writer.writeheader()
        writer.writerows(packets)
    print(f"Wrote {len(packets)} packets to {csv_file}")

def write_json(packets, json_file):
    with open(json_file, 'w') as f:
        json.dump(packets, f, indent=4)
    print(f"Wrote {len(packets)} packets to {json_file}")

# --- Validation Functions ---
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_packet(p):
    if p.get('src_ip') and p.get('dst_ip'):
        return validate_ip(p['src_ip']) and validate_ip(p['dst_ip'])
    return True

def read_csv_and_validate(csv_file):
    with open(csv_file) as f:
        reader = csv.DictReader(f)
        packets = [row for row in reader]
    valid = [p for p in packets if validate_packet(p)]
    print(f"Valid packets: {len(valid)}/{len(packets)}")

# --- Graceful exit ---
running = True

def signal_handler(sig, frame):
    global running
    print("Stopping capture...")
    running = False

signal.signal(signal.SIGINT, signal_handler)

# --- Main Execution ---
def sniff_interface(interface, packets_buffer):
    print(f"Started sniffing on {interface}")
    def handle_packet(pkt):
        summary = packet_summary(pkt, interface)
        if summary:
            packets_buffer.append(summary)

    while running:
        sniff(prn=handle_packet, store=0, iface=interface, timeout=1)

def main():
    print("Starting continuous packet capture on all interfaces...")
    packets_buffer = []
    start_time = datetime.now()
    interfaces = get_if_list()
    print(f"Interfaces detected: {interfaces}")

    # Start a thread for each interface
    threads = []
    for iface in interfaces:
        t = threading.Thread(target=sniff_interface, args=(iface, packets_buffer), daemon=True)
        t.start()
        threads.append(t)

    while running:
        now = datetime.now()
        if (now - start_time) >= timedelta(minutes=1):
            if packets_buffer:
                txt_file, csv_file, json_file = generate_file_paths()
                write_txt(packets_buffer, txt_file)
                write_csv(packets_buffer, csv_file)
                write_json(packets_buffer, json_file)
                read_csv_and_validate(csv_file)
                packets_buffer.clear()
            start_time = now

    for t in threads:
        t.join()

if __name__ == '__main__':
    main()
