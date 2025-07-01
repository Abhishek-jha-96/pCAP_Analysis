import re
import traceback
from collections import Counter
from typing import Optional
from scapy.all import rdpcap
from analysis import (
    detect_cleartext_credentials,
    detect_ddos, 
    detect_excessive_icmp, 
    detect_excessive_syn, 
    detect_intrusion, 
    detect_large_dns_responses, 
    detect_large_packets, 
    detect_port_scanning, 
    detect_threat_hunting, 
    detect_unsolicited_arp,
    detect_unusual_ports,
    flag_suspicious_ips,
    generate_timeline,
    detect_suspicious_domains,
    detect_malicious_dns_queries,
    detect_large_post_requests,
    detect_tls_anomalies,
    detect_non_standard_protocols
)
from helpers import file_hash
from report_gen import export_soc_threat_report

def filter_protocols(packets):
    groups = {"TCP": [], "UDP": [], "HTTP": [], "HTTPS": [], "DNS": []}
    for pkt in packets:
        if pkt.haslayer("TCP"):
            groups["TCP"].append(pkt)
            if pkt.haslayer("Raw") and pkt["TCP"].dport in [80, 443] or pkt["TCP"].sport in [80, 443]:
                if pkt["TCP"].dport == 80 or pkt["TCP"].sport == 80:
                    groups["HTTP"].append(pkt)
                if pkt["TCP"].dport == 443 or pkt["TCP"].sport == 443:
                    groups["HTTPS"].append(pkt)
        if pkt.haslayer("UDP"):
            groups["UDP"].append(pkt)
        if pkt.haslayer("DNS"):
            groups["DNS"].append(pkt)
    return groups

def extract_top_http_hosts(packets, top_n=10):
    counter = Counter()
    for pkt in packets:
        if pkt.haslayer("Raw"):
            try:
                payload = pkt["Raw"].load.decode("utf-8", errors="ignore")
                match = re.search(r"Host:\s*([^\r\n]+)", payload, re.IGNORECASE)
                if match:
                    counter[match.group(1).strip()] += 1
            except:
                continue
    return counter.most_common(top_n)

def extract_top_dns_queries(packets, top_n=10):
    counter = Counter()
    for pkt in packets:
        if pkt.haslayer("DNSQR"):
            try:
                query = pkt["DNSQR"].qname.decode(errors="ignore").rstrip(".")
                counter[query] += 1
            except:
                continue
    return counter.most_common(top_n)

def extract_anomalous_packets(anomaly_results):
    indices = set()
    for result in anomaly_results.values():
        if isinstance(result, dict):
            # Recursive search in dictionaries
            for val in result.values():
                if isinstance(val, list):
                    for entry in val:
                        if isinstance(entry, dict) and "packet_index" in entry:
                            indices.add(entry["packet_index"])
        elif isinstance(result, list):
            for entry in result:
                if isinstance(entry, dict) and "packet_index" in entry:
                    indices.add(entry["packet_index"])
    return sorted(indices)

def generate_final_report(packets, protocols, anomalies, anomaly_indices):
    return {
        "Executive Summary": {
            "Total Packets": len(packets),
            "Suspicious Packets": len(anomaly_indices),
            "Alerts by Category": {
                k: len(v) if isinstance(v, list)
                else len(v.get("suspicious_requests", []))
                if isinstance(v, dict) and "suspicious_requests" in v
                else v if isinstance(v, int) else 1
                for k, v in anomalies.items()
                if k != "Timeline of Detected Anomalies"
            }
        },
        "Top 10 HTTP Hosts": extract_top_http_hosts(protocols["HTTP"]),
        "Top 10 DNS Queries": extract_top_dns_queries(protocols["DNS"]),
        "Suspicious IPs": anomalies.get("IP Reputation / Abuse Indicators", {}).get("flagged_ips", []),
        "Credential or Token Leaks": anomalies.get("Credential/Token Leakage", {}).get("leak_indicators", [])[:5],
        "Timeline of Threat Activity": anomalies.get("Timeline of Detected Anomalies", [])
    }

def analyze_pcap(file_path):
    packets = rdpcap(file_path)
    protocols = filter_protocols(packets)

    print(f"[*] Analyzing: {file_path}")
    print(f"[*] File Hash: {file_hash(file_path)}")

    anomalies = {
        "Uncommon Destination Ports (TCP/UDP)": detect_unusual_ports(protocols["TCP"] + protocols["UDP"], mode="any"),
        "Possible DDoS Attacks (IP)": detect_ddos(packets),
        "Large Packets (All)": detect_large_packets(packets),
        "Unsolicited ARP Replies": detect_unsolicited_arp(packets),
        "Large DNS Responses": detect_large_dns_responses(protocols["DNS"]),
        "Excessive ICMP Echo Requests": detect_excessive_icmp(packets),
        "Excessive TCP SYN": detect_excessive_syn(protocols["TCP"]),
        "Port Scanning Attempts": detect_port_scanning(protocols["TCP"] + protocols["UDP"]),
        "Intrusion Detection": detect_intrusion(packets),
        "Threat Hunting Indicators": detect_threat_hunting(packets),
        "Suspicious Domain Requests": detect_suspicious_domains(protocols["HTTP"]),
        "Malicious DNS Queries": detect_malicious_dns_queries(protocols["DNS"]),
        "Outbound Connections to Odd Ports": detect_unusual_ports(packets, mode="outbound"),
        "Large POST Requests": detect_large_post_requests(protocols["HTTP"]),
        "TLS Client Hello Anomalies": detect_tls_anomalies(protocols["HTTPS"]),
        "Non-Standard Protocols on Unusual Ports": detect_non_standard_protocols(protocols["TCP"]),
        "Credential/Token Leakage": detect_cleartext_credentials(protocols["HTTP"]),
        "IP Reputation / Abuse Indicators": flag_suspicious_ips(packets, reputation_db=None),
    }

    anomaly_indices = extract_anomalous_packets(anomalies)
    suspicious_packets = [packets[i] for i in anomaly_indices]

    # Generate timelines based on suspicious packets only
    anomalies["Timeline of Detected Anomalies"] = generate_timeline(suspicious_packets, window=5)
    report = generate_final_report(packets, protocols, anomalies, anomaly_indices)

    return report

def format_output(data, max_items=10):
    if isinstance(data, dict) and len(data) > max_items:
        return dict(list(data.items())[:max_items] + [("...", f"({len(data) - max_items} more truncated)")])
    if isinstance(data, list) and len(data) > max_items:
        return data[:max_items] + [f"... ({len(data) - max_items} more items truncated)"]
    return data

if __name__ == "__main__":
    import typer
    from rich.console import Console
    from rich.table import Table

    console = Console()

    def analyze(file: str, verbose: bool = False, md: Optional[str] = None):
        try:
            report = analyze_pcap(file)
            if md:
                export_soc_threat_report(report, output_path=md, file_name=file, analyst="Name")

            for section, content in report.items():
                console.rule(f"[bold red]{section}")
                content = content if verbose else format_output(content)

                if isinstance(content, dict):
                    table = Table(show_header=True, header_style="bold blue")
                    table.add_column("Key", style="cyan")
                    table.add_column("Value", style="white")
                    for k, v in content.items():
                        val = str(v)
                        table.add_row(k, val[:100] + "..." if len(val) > 100 else val)
                    console.print(table)
                elif isinstance(content, list):
                    for item in content:
                        console.print(f"- {item}")
                else:
                    console.print(str(content))
        except FileNotFoundError:
            console.print(f"[red]Error: File '{file}' not found.[/red]")
        except Exception as e:
            console.print(f"[red]Error while processing data file.[/red]")

    typer.run(analyze)
