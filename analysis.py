from scapy.all import *
from collections import defaultdict, Counter
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, DNSQR
import datetime
import re


# Function to detect excessive traffic (DDoS) based on packet rate
def detect_ddos(packets):
    ip_counts = defaultdict(int)
    for pkt in packets:
        if IP in pkt:
            ip_counts[pkt[IP].src] += 1
    # Threshold for excessive traffic
    return {ip: count for ip, count in ip_counts.items() if count > 1000}

# Function to detect unusually large packets


def detect_large_packets(packets, threshold=1500):
    large_packets = [pkt for pkt in packets if len(pkt) > threshold]
    return large_packets

# Function to detect unsolicited ARP replies


def detect_unsolicited_arp(packets):
    arp_replies = []
    for pkt in packets:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
            arp_replies.append(pkt)
    return arp_replies

# Function to detect unusually large DNS responses


def detect_large_dns_responses(packets, threshold=512):
    """	Unusual DNS queries, data exfiltration flows"""
    large_dns = []
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(UDP) and len(pkt) > threshold:
            large_dns.append(pkt)
    return large_dns

# Function to detect excessive ICMP Echo requests


def detect_excessive_icmp(packets, threshold=100):
    icmp_requests = defaultdict(int)
    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            icmp_requests[pkt[IP].src] += 1
    return {ip: count for ip, count in icmp_requests.items() if count > threshold}

# Function to detect excessive TCP SYN packets


def detect_excessive_syn(packets, threshold=200):
    syn_counts = defaultdict(int)
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt[TCP].flags == 'S':
            syn_counts[pkt[IP].src] += 1
    return {ip: count for ip, count in syn_counts.items() if count > threshold}

# Function to detect IPs scanning excessive ports


def detect_port_scanning(packets, threshold=50):
    scan_counts = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            scan_counts[pkt[IP].src].add(pkt.dport)
    return {ip: len(ports) for ip, ports in scan_counts.items() if len(ports) > threshold}


def detect_intrusion(packets, syn_threshold=200, portscan_threshold=50):
    intrusion_alerts = {}

    # Detect SYN floods
    syn_counts = defaultdict(int)
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt[TCP].flags == 'S' and pkt.haslayer(IP):
            syn_counts[pkt[IP].src] += 1
    suspicious_syn = {ip: count for ip,
                      count in syn_counts.items() if count > syn_threshold}
    if suspicious_syn:
        intrusion_alerts["SYN Flood Suspects"] = suspicious_syn

    # Detect port scans
    scan_counts = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            scan_counts[pkt[IP].src].add(pkt.dport)
    port_scanners = {ip: len(ports) for ip, ports in scan_counts.items() if len(
        ports) > portscan_threshold}
    if port_scanners:
        intrusion_alerts["Port Scan Suspects"] = port_scanners

    # Detect small-sized packet floods (e.g., brute force, malformed scans)
    small_packet_counts = defaultdict(int)
    for pkt in packets:
        if pkt.haslayer(IP) and len(pkt) < 100:  # 100 bytes is a common cut-off
            small_packet_counts[pkt[IP].src] += 1
    packet_flooders = {ip: count for ip,
                       count in small_packet_counts.items() if count > 300}
    if packet_flooders:
        intrusion_alerts["Small Packet Flooders"] = packet_flooders

    return intrusion_alerts or {"Intrusion Indicators": "None Detected"}


def detect_threat_hunting(packets):
    from collections import Counter
    threat_signals = {}

    # Count protocols (Uncommon protocols might indicate probing)
    protocol_counter = Counter()
    for pkt in packets:
        if pkt.haslayer(IP):
            proto = pkt[IP].proto
            protocol_counter[proto] += 1
    rare_protocols = {proto: count for proto,
                      count in protocol_counter.items() if count < 10}
    if rare_protocols:
        threat_signals["Rare IP Protocols"] = rare_protocols

    # Suspicious DNS queries (length or frequency)
    long_dns_queries = []
    dns_counts = defaultdict(int)
    for pkt in packets:
        if pkt.haslayer(DNSQR):
            query_name = pkt[DNSQR].qname.decode(errors="ignore")
            dns_counts[query_name] += 1
            if len(query_name) > 50:
                long_dns_queries.append(query_name)
    frequent_dns = {name: count for name,
                    count in dns_counts.items() if count > 100}
    if long_dns_queries:
        threat_signals["Long DNS Queries"] = long_dns_queries
    if frequent_dns:
        threat_signals["Frequent DNS Queries"] = frequent_dns

    # Internal scanning (same subnet)
    subnet_scan = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            if src.startswith("192.168.") and dst.startswith("192.168.") and src != dst:
                subnet_scan[src].add(dst)
    internal_scanners = {
        ip: len(targets) for ip, targets in subnet_scan.items() if len(targets) > 10}
    if internal_scanners:
        threat_signals["Lateral Movement / Internal Scanning"] = internal_scanners

    return threat_signals or {"Threat Hunting Indicators": "None Detected"}


def generate_timeline(packets, window=1):
    timeline = defaultdict(lambda: {
        "packet_count": 0,
        "protocols": defaultdict(int),
        "sources": set(),
        "destinations": set()
    })

    if not packets:
        return {}

    start_time = float(packets[0].time)

    for pkt in packets:
        timestamp = float(pkt.time)
        time_bucket = int((timestamp - start_time) // window)

        if IP in pkt:
            proto = "OTHER"
            if TCP in pkt:
                proto = "TCP"
            elif UDP in pkt:
                proto = "UDP"
            elif ICMP in pkt:
                proto = "ICMP"

            bucket = timeline[time_bucket]
            bucket["packet_count"] += 1
            bucket["protocols"][proto] += 1
            bucket["sources"].add(pkt[IP].src)
            bucket["destinations"].add(pkt[IP].dst)

    # Convert to ordered timeline with human-readable timestamps
    timeline_output = []
    for time_bucket in sorted(timeline.keys()):
        bucket_time = start_time + time_bucket * window
        ts = datetime.datetime.fromtimestamp(
            bucket_time).strftime('%Y-%m-%d %H:%M:%S')
        entry = timeline[time_bucket]
        timeline_output.append({
            "time": ts,
            "packet_count": entry["packet_count"],
            "protocols": dict(entry["protocols"]),
            "unique_sources": list(entry["sources"]),
            "unique_destinations": list(entry["destinations"])
        })

    return timeline_output


def detect_suspicious_domains(packets):
    """Detect HTTP requests to suspicious domains and TLDs"""
    suspicious_tlds = {'.ru', '.xyz', '.top', '.tk',
                       '.ml', '.ga', '.cf', '.pw', '.cc', '.info', '.biz'}
    suspicious_domains = []
    domain_stats = defaultdict(int)

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')

                # Look for HTTP Host headers
                host_match = re.search(
                    r'Host:\s*([^\r\n]+)', payload, re.IGNORECASE)
                if host_match:
                    host = host_match.group(1).strip().lower()
                    domain_stats[host] += 1

                    # Check for suspicious TLDs
                    for tld in suspicious_tlds:
                        if host.endswith(tld):
                            suspicious_domains.append({
                                "domain": host,
                                "packet_index": idx,
                                "src_ip": pkt[IP].src if pkt.haslayer(IP) else "N/A",
                                "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else "N/A",
                                "reason": f"Suspicious TLD: {tld}"
                            })

                # Look for GET/POST requests with full URLs
                url_match = re.search(
                    r'(?:GET|POST)\s+http://([^/\s]+)', payload, re.IGNORECASE)
                if url_match:
                    domain = url_match.group(1).lower()
                    domain_stats[domain] += 1

                    for tld in suspicious_tlds:
                        if domain.endswith(tld):
                            suspicious_domains.append({
                                "domain": domain,
                                "packet_index": idx,
                                "src_ip": pkt[IP].src if pkt.haslayer(IP) else "N/A",
                                "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else "N/A",
                                "reason": f"Suspicious TLD: {tld}"
                            })

            except (UnicodeDecodeError, AttributeError):
                continue

    return {
        "suspicious_requests": suspicious_domains,
        "domain_frequency": dict(domain_stats)
    }


def detect_malicious_dns_queries(packets):
    """Detect DNS queries to known patterns of malicious domains"""
    suspicious_patterns = [
        r'[a-z0-9]{20,}\.(?:com|net|org)',  # Long random strings
        r'\d+\.\d+\.\d+\.\d+\.in-addr\.arpa',  # Reverse DNS lookups
        r'.*\.(?:tk|ml|ga|cf|pw)$',  # Free/suspicious TLDs
        r'[a-f0-9]{32,}\..*',  # Hex strings (possible C2)
        r'.*dga.*',  # Domain Generation Algorithm patterns
    ]

    suspicious_dns = []
    query_stats = defaultdict(int)

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(DNSQR):
            try:
                query_name = pkt[DNSQR].qname.decode(
                    'utf-8', errors='ignore').rstrip('.')
                query_stats[query_name] += 1

                # Check against suspicious patterns
                for pattern in suspicious_patterns:
                    if re.match(pattern, query_name, re.IGNORECASE):
                        suspicious_dns.append({
                            "query": query_name,
                            "packet_index": idx,
                            "src_ip": pkt[IP].src if pkt.haslayer(IP) else "N/A",
                            "pattern_matched": pattern,
                            "query_type": pkt[DNSQR].qtype
                        })
                        break

                # Check for domain age indicators (very short domains often suspicious)
                if len(query_name) < 5 and '.' in query_name:
                    suspicious_dns.append({
                        "query": query_name,
                        "packet_index": idx,
                        "src_ip": pkt[IP].src if pkt.haslayer(IP) else "N/A",
                        "pattern_matched": "Very short domain",
                        "query_type": pkt[DNSQR].qtype
                    })

            except (UnicodeDecodeError, AttributeError):
                continue

    return {
        "suspicious_queries": suspicious_dns,
        "query_frequency": dict(query_stats)
    }


def detect_large_post_requests(packets):
    """Detect unusually large HTTP POST requests"""
    large_posts = []
    post_stats = []

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')

                # Look for POST requests
                if payload.startswith('POST'):
                    content_length_match = re.search(
                        r'Content-Length:\s*(\d+)', payload, re.IGNORECASE)
                    if content_length_match:
                        content_length = int(content_length_match.group(1))
                        post_stats.append(content_length)

                        # Flag large POST requests (>10KB)
                        if content_length > 10240:
                            # Extract target URL
                            url_match = re.search(r'POST\s+([^\s]+)', payload)
                            url = url_match.group(
                                1) if url_match else "Unknown"

                            # Extract Host header
                            host_match = re.search(
                                r'Host:\s*([^\r\n]+)', payload)
                            host = host_match.group(
                                1).strip() if host_match else "Unknown"

                            large_posts.append({
                                "src_ip": pkt[IP].src if pkt.haslayer(IP) else "N/A",
                                "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else "N/A",
                                "host": host,
                                "url": url,
                                "content_length": content_length,
                                "packet_index": idx,
                                "packet_size": len(pkt)
                            })

            except (UnicodeDecodeError, AttributeError, ValueError):
                continue

    return {
        "large_posts": large_posts,
        "post_size_stats": {
            "total_posts": len(post_stats),
            "avg_size": sum(post_stats) / len(post_stats) if post_stats else 0,
            "max_size": max(post_stats) if post_stats else 0
        }
    }


def detect_tls_anomalies(packets):
    """Detect TLS Client Hello fingerprint anomalies"""
    tls_handshakes = []
    cipher_suites = defaultdict(int)

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt[TCP].dport == 443:
            try:
                payload = pkt[Raw].load

                # Look for TLS Client Hello (simplified detection)
                # TLS record type 22 (handshake), version, length, handshake type 1 (client hello)
                if len(payload) > 5 and payload[0] == 0x16:  # TLS Handshake
                    tls_version = (payload[1] << 8) | payload[2]

                    if len(payload) > 43:  # Minimum for basic client hello
                        # Extract SNI if present (simplified)
                        sni = "Unknown"
                        try:
                            # Look for SNI extension (very simplified)
                            # Server Name extension
                            if b'\x00\x00' in payload[43:]:
                                sni_start = payload.find(b'\x00\x00', 43)
                                if sni_start > 0 and sni_start + 9 < len(payload):
                                    sni_len = (
                                        payload[sni_start + 7] << 8) | payload[sni_start + 8]
                                    if sni_start + 9 + sni_len <= len(payload):
                                        sni = payload[sni_start + 9:sni_start + 9 +
                                                      sni_len].decode('utf-8', errors='ignore')
                        except:
                            pass

                        tls_handshakes.append({
                            "src_ip": pkt[IP].src if pkt.haslayer(IP) else "N/A",
                            "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else "N/A",
                            "tls_version": f"0x{tls_version:04x}",
                            "sni": sni,
                            "packet_index": idx,
                            "handshake_size": len(payload)
                        })

            except (UnicodeDecodeError, AttributeError, IndexError):
                continue

    return {
        "tls_handshakes": tls_handshakes[:20],  # Limit output
        "handshake_count": len(tls_handshakes)
    }


def detect_non_standard_protocols(packets):
    """Detect non-standard protocols on unusual ports"""
    protocol_signatures = {
        'IRC': [b'NICK ', b'USER ', b'JOIN ', b'PRIVMSG'],
        'FTP': [b'220 ', b'USER ', b'PASS ', b'RETR ', b'STOR'],
        'SMTP': [b'HELO ', b'EHLO ', b'MAIL FROM:', b'RCPT TO:'],
        'POP3': [b'+OK ', b'USER ', b'PASS ', b'RETR'],
        'Telnet': [b'\xff\xfd', b'\xff\xfe', b'\xff\xfb', b'\xff\xfc'],
        'SSH': [b'SSH-'],
        'HTTP': [b'GET ', b'POST ', b'HTTP/'],
    }

    unusual_protocols = []

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport

            # Check for protocol signatures
            for protocol, signatures in protocol_signatures.items():
                for signature in signatures:
                    if signature in payload[:50]:  # Check first 50 bytes
                        # Check if it's on an unusual port for this protocol
                        standard_ports = {
                            'IRC': [6667, 6668, 6669, 194],
                            'FTP': [21, 20],
                            'SMTP': [25, 587, 465],
                            'POP3': [110, 995],
                            'Telnet': [23],
                            'SSH': [22],
                            'HTTP': [80, 8080, 8000, 3000]
                        }

                        if dst_port not in standard_ports.get(protocol, []):
                            unusual_protocols.append({
                                "protocol": protocol,
                                "src_ip": pkt[IP].src if pkt.haslayer(IP) else "N/A",
                                "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else "N/A",
                                "src_port": src_port,
                                "dst_port": dst_port,
                                "signature": signature.decode('utf-8', errors='ignore'),
                                "packet_index": idx
                            })
                        break

    return {
        "unusual_protocols": unusual_protocols,
        "protocol_count": len(unusual_protocols)
    }

def detect_cleartext_credentials(packets):
    leaks = []
    keywords = ["password", "passwd", "token", "apikey", "authorization", "auth", "secret"]

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
                if any(kw in payload for kw in keywords):
                    leaks.append({
                        "packet_index": idx,
                        "src_ip": pkt[IP].src if pkt.haslayer(IP) else "N/A",
                        "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else "N/A",
                        "snippet": payload[:100]
                    })
            except Exception:
                continue

    return {"leak_indicators": leaks, "leak_count": len(leaks)}


def flag_suspicious_ips(packets, reputation_db=None):
    suspicious_ips = defaultdict(set)

    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst

            # Simulated scoring
            if reputation_db:
                if src in reputation_db:
                    suspicious_ips[src].add("source")
                if dst in reputation_db:
                    suspicious_ips[dst].add("destination")

            # Simple heuristic: flag external + private IP mix
            if (src.startswith("192.168.") and not dst.startswith("192.168.")) or \
               (dst.startswith("192.168.") and not src.startswith("192.168.")):
                continue  # common NAT traffic
            if not src.startswith("192.") and not dst.startswith("192."):
                suspicious_ips[src].add("external")
                suspicious_ips[dst].add("external")

    return {
        "flagged_ips": list(suspicious_ips.keys()),
        "ip_roles": {ip: list(roles) for ip, roles in suspicious_ips.items()}
    }

def detect_unusual_ports(packets, mode="any", max_examples=3, include_port_stats=True):
    common_tcp_ports = {80, 443, 21, 22, 25, 110, 143, 3389}
    common_udp_ports = {53, 67, 68, 123, 161, 162}
    common_outbound_ports = common_tcp_ports | {993, 995, 587, 465, 53, 23}

    unusual_ports = []
    port_stats = defaultdict(lambda: {"count": 0, "protocol": "", "examples": []})

    for idx, pkt in enumerate(packets):
        if not pkt.haslayer(IP) or not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        is_private_src = src_ip.startswith(("192.168.", "10.", "172."))
        is_private_dst = dst_ip.startswith(("192.168.", "10.", "172."))

        if mode == "outbound" and not (is_private_src and not is_private_dst):
            continue

        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            proto = "TCP"
            is_common = dport in common_tcp_ports if mode != "outbound" else dport in common_outbound_ports
        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            proto = "UDP"
            is_common = dport in common_udp_ports if mode != "outbound" else dport in common_outbound_ports
        else:
            continue

        if not is_common:
            unusual_ports.append({
                "packet_index": idx,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dport,
                "protocol": proto
            })

        # Always collect port stats
        stat = port_stats[dport]
        stat["count"] += 1
        stat["protocol"] = proto
        if len(stat["examples"]) < max_examples:
            stat["examples"].append({
                "index": idx,
                "src": src_ip,
                "dst": dst_ip
            })

    return {
        "unusual_ports": unusual_ports[:50],
        "port_statistics": dict(sorted(port_stats.items(), key=lambda x: x[1]["count"], reverse=True)) if include_port_stats else {}
    }