import datetime
import os


def export_soc_threat_report(report: dict, output_path: str, file_name: str = "Unknown", analyst: str = "Analyst", tlp: str = "TLP:AMBER"):
    def format_table(headers, rows):
        output = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
        for row in rows:
            output.append("| " + " | ".join(str(item) for item in row) + " |")
        return "\n".join(output)

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# THREAT INTELLIGENCE REPORT",
        f"**Report Type**: Network Anomaly Report",
        f"**Source**: PCAP File Analysis",
        f"**Analyst**: {analyst}",
        f"**Date**: {now}",
        f"**Confidence**: High",
        f"**Severity**: Medium-High",
        f"**TLP**: {tlp}",
        "\n---",
        "## Executive Summary",
        "> Network packet capture analysis revealed multiple indicators of suspicious and potentially malicious activity. Notable findings include DNS queries to suspicious TLDs, credential leakage in cleartext, and outbound connections on odd ports.",
        "\n---",
        "## Technical Details",
        format_table(["Category", "Description"], [
            ["File Analyzed", file_name],
            ["Total Packets", report["Executive Summary"].get("Total Packets", "?")],
            ["Suspicious Packets", report["Executive Summary"].get("Suspicious Packets", "?")],
        ]),
        "\n---",
        "## Detected Threats & Indicators"
    ]

    alerts = report.get("Executive Summary", {}).get("Alerts by Category", {})
    for threat, count in alerts.items():
        lines.append(f"### {threat}")
        lines.append(f"- **Count**: {count}")

    lines += [
        "\n## Top Communication Targets",
        "### HTTP Hosts",
        format_table(["Host", "Count"], report.get("Top 10 HTTP Hosts", [])),
        "### DNS Queries",
        format_table(["Domain", "Count"], report.get("Top 10 DNS Queries", [])),
        "\n## Suspicious IPs (Flagged by Reputation Services)"
    ]

    flagged_ips = report.get("Suspicious IPs", [])
    if flagged_ips:
        if isinstance(flagged_ips[0], dict):
            rows = [(ip.get("ip", "?"), ip.get("reason", "Unknown"), ip.get("abuse_score", "?")) for ip in flagged_ips]
            lines.append(format_table(["IP", "Reason", "Abuse Score"], rows))
        else:
            # Assume it's a list of raw IP strings
            rows = [(ip,) for ip in flagged_ips]
            lines.append(format_table(["IP"], rows))
    else:
        lines.append("- None found")

    lines.append("\n## Timeline of Detected Anomalies")
    timeline = report.get("Timeline of Threat Activity", [])
    if timeline and isinstance(timeline[0], dict):
        rows = []
        for entry in timeline:
            time = entry.get("time", "N/A")
            count = entry.get("packet_count", 0)
            protocols = ", ".join(f"{proto}:{count}" for proto, count in entry.get("protocols", {}).items())
            srcs = ", ".join(entry.get("unique_sources", [])[:3]) + (" ..." if len(entry.get("unique_sources", [])) > 3 else "")
            dsts = ", ".join(entry.get("unique_destinations", [])[:3]) + (" ..." if len(entry.get("unique_destinations", [])) > 3 else "")
            rows.append((time, count, protocols, srcs, dsts))

        lines.append(format_table(
            ["Time", "Packets", "Protocols", "Top Sources", "Top Destinations"],
            rows
        ))
    else:
        lines.append("- No notable activity window")

    lines.append("\n## Recommended Actions")
    lines += [
        "- [ ] Block outbound traffic to flagged IPs and domains at perimeter firewall",
        "- [ ] Isolate host(s) initiating connections on suspicious ports",
        "- [ ] Reset exposed user credentials",
        "- [ ] Review internal logs for additional connections to suspicious domains",
        "- [ ] Enforce TLS for all services handling credentials"
    ]

    lines.append("\n## Indicators of Compromise (IOCs)")
    lines.append("```text")

    for domain in [d[0] for d in report.get("Top 10 DNS Queries", [])]:
        lines.append(domain)
    for host in [h[0] for h in report.get("Top 10 HTTP Hosts", [])]:
        lines.append(host)
    for ip in flagged_ips:
        # Change once added Abuse score.
        lines.append(ip)
    lines.append("```")

    dir_path = os.path.dirname(output_path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))

    print(f"[✓] SOC-style threat report saved to: {output_path}")
