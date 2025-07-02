# THREAT INTELLIGENCE REPORT
**Report Type**: Network Anomaly Report
**Source**: PCAP File Analysis
**Analyst**: Name
**Date**: 2025-07-02 12:52:32
**Confidence**: High
**Severity**: Medium-High
**TLP**: TLP:AMBER

---
## Executive Summary
> Network packet capture analysis revealed multiple indicators of suspicious and potentially malicious activity. Notable findings include DNS queries to suspicious TLDs, credential leakage in cleartext, and outbound connections on odd ports.

---
## Technical Details
| Category | Description |
| --- | --- |
| File Analyzed | data.pcap |
| Total Packets | 48877 |
| Suspicious Packets | 428 |

---
## Detected Threats & Indicators
### Large Packets (All)
- **Count**: 81
### Excessive ICMP Echo Requests
- **Count**: 1
### Excessive TCP SYN
- **Count**: 1
### Unsolicited ARP Replies
- **Count**: 126
### Port Scanning Attempts
- **Count**: 1
### Possible DDoS Attacks (IP)
- **Count**: 1
### Intrusion Detection
- **Count**: 1
### Non-Standard Protocols on Unusual Ports
- **Count**: 1
### Outbound Connections to Odd Ports
- **Count**: 1
### TLS Client Hello Anomalies
- **Count**: 1
### Large DNS Responses
- **Count**: 0
### Uncommon Destination Ports (TCP/UDP)
- **Count**: 1
### Threat Hunting Indicators
- **Count**: 1
### Malicious DNS Queries
- **Count**: 1
### Suspicious Domain Requests
- **Count**: 0
### Large POST Requests
- **Count**: 1
### Credential/Token Leakage
- **Count**: 1
### IP Reputation / Abuse Indicators
- **Count**: 1
### Timeline of Activity
- **Count**: 240

## Top Communication Targets
### HTTP Hosts
| Host | Count |
| --- | --- |
| event-datamicrosoft.live | 27 |
| varying-rentals-calgary-predict.trycloudflare.com | 18 |
| windows-msgas.com | 17 |
| ctldl.windowsupdate.com | 2 |
| www.msftconnecttest.com | 1 |
| event-time-microsoft.org | 1 |
| eventdata-microsoft.live | 1 |
| acroipm2.adobe.com | 1 |
### DNS Queries
| Domain | Count |
| --- | --- |
| wpad.massfriction.com | 50 |
| edge.microsoft.com | 22 |
| www.bing.com | 16 |
| windows-msgas.com | 14 |
| varying-rentals-calgary-predict.trycloudflare.com | 14 |
| event-datamicrosoft.live | 14 |
| www.google.com | 12 |
| s.clarity.ms | 12 |
| login.microsoftonline.com | 10 |
| config.edge.skype.com | 9 |

## Suspicious IPs (Flagged by AbuseIPDB)
- No suspicious IPs detected via AbuseIPDB

## Timeline of Detected Anomalies
| Time | Packets | Protocols | Top Sources | Top Destinations |
| --- | --- | --- | --- | --- |
| 2025-06-13 21:03:55 | 54 | UDP:31, TCP:23 | 10.6.13.133, 0.0.0.0, 10.6.13.3 ... | 10.6.13.255, 10.6.13.133, 255.255.255.255 ... |
| 2025-06-13 21:04:00 | 10 | UDP:6, TCP:4 | 10.6.13.133 | 239.255.255.250, 10.6.13.255, 104.208.203.90 |
| 2025-06-13 21:04:05 | 45 | UDP:5, TCP:40 | 10.6.13.3, 10.6.13.133 | 239.255.255.250, 10.6.13.3, 10.6.13.133 |
| 2025-06-13 21:04:10 | 32 | TCP:20, UDP:12 | 20.190.135.6, 10.6.13.133, 10.6.13.3 ... | 20.190.135.6, 10.6.13.133, 104.208.203.90 ... |
| 2025-06-13 21:04:15 | 57 | UDP:2, TCP:55 | 23.212.185.76, 13.107.42.16, 10.6.13.133 | 10.6.13.133, 10.6.13.3, 13.107.42.16 ... |
| 2025-06-13 21:04:20 | 3 | TCP:3 | 10.6.13.3, 10.6.13.133 | 10.6.13.3, 10.6.13.133 |
| 2025-06-13 21:04:25 | 5 | TCP:2, UDP:3 | 23.198.7.180, 10.6.13.133, 150.171.28.11 | 224.0.0.251, 10.6.13.133 |
| 2025-06-13 21:04:35 | 21 | TCP:21 | 142.250.115.99, 142.250.113.95, 10.6.13.133 ... | 142.250.115.99, 10.6.13.133, 142.251.186.138 |
| 2025-06-13 21:04:40 | 8 | TCP:8 | 142.250.115.99, 10.6.13.133 | 142.250.115.99, 205.174.24.80, 10.6.13.133 |
| 2025-06-13 21:04:45 | 33 | TCP:32, UDP:1 | 150.171.27.11, 10.6.13.133, 173.194.208.94 ... | 150.171.27.11, 10.6.13.133, 109.61.92.48 ... |
| 2025-06-13 21:05:00 | 2 | TCP:2 | 10.6.13.133 | 204.79.197.222 |
| 2025-06-13 21:05:10 | 1 | UDP:1 | 10.6.13.133 | 10.6.13.3 |
| 2025-06-13 21:05:20 | 9 | UDP:9 | 10.6.13.133 | 239.255.255.250 |
| 2025-06-13 21:05:25 | 4 | UDP:4 | 10.6.13.133 | 239.255.255.250 |
| 2025-06-13 21:05:30 | 1 | UDP:1 | 23.198.7.186 | 10.6.13.133 |
| 2025-06-13 21:06:20 | 1 | TCP:1 | 10.6.13.133 | 104.21.112.1 |
| 2025-06-13 21:06:30 | 3 | TCP:3 | 83.137.149.15 | 10.6.13.133 |
| 2025-06-13 21:06:35 | 3 | TCP:3 | 83.137.149.15 | 10.6.13.133 |
| 2025-06-13 21:06:40 | 16 | TCP:16 | 83.137.149.15, 10.6.13.133 | 83.137.149.15, 10.6.13.133 |
| 2025-06-13 21:06:45 | 23 | TCP:23 | 83.137.149.15, 10.6.13.133 | 83.137.149.15, 10.6.13.133 |
| 2025-06-13 21:06:50 | 11 | TCP:11 | 83.137.149.15, 10.6.13.133 | 83.137.149.15, 10.6.13.133 |
| 2025-06-13 21:06:55 | 18 | TCP:18 | 83.137.149.15, 10.6.13.133 | 83.137.149.15, 10.6.13.133 |
| 2025-06-13 21:07:00 | 15 | TCP:15 | 83.137.149.15, 10.6.13.133 | 83.137.149.15, 10.6.13.133 |
| 2025-06-13 21:07:05 | 8 | TCP:8 | 83.137.149.15, 10.6.13.133 | 83.137.149.15, 10.6.13.133 |
| 2025-06-13 21:07:20 | 2 | TCP:2 | 10.6.13.133 | 104.21.16.1 |
| 2025-06-13 21:08:55 | 2 | TCP:2 | 104.16.230.132 | 10.6.13.133 |
| 2025-06-13 21:09:10 | 2 | TCP:2 | 10.6.13.133 | 10.6.13.3 |
| 2025-06-13 21:09:25 | 1 | TCP:1 | 10.6.13.133 | 104.21.16.1 |
| 2025-06-13 21:11:30 | 1 | TCP:1 | 10.6.13.133 | 10.6.13.3 |
| 2025-06-13 21:11:55 | 1 | TCP:1 | 10.6.13.133 | 104.21.16.1 |
| 2025-06-13 21:13:25 | 1 | TCP:1 | 104.21.16.1 | 10.6.13.133 |
| 2025-06-13 21:14:05 | 1 | TCP:1 | 10.6.13.133 | 10.6.13.3 |
| 2025-06-13 21:15:25 | 1 | TCP:1 | 10.6.13.133 | 104.21.16.1 |
| 2025-06-13 21:15:30 | 1 | TCP:1 | 10.6.13.133 | 10.6.13.3 |
| 2025-06-13 21:15:55 | 1 | TCP:1 | 104.21.112.1 | 10.6.13.133 |
| 2025-06-13 21:16:25 | 3 | TCP:3 | 10.6.13.133 | 104.21.16.1 |
| 2025-06-13 21:17:25 | 1 | TCP:1 | 104.16.230.132 | 10.6.13.133 |
| 2025-06-13 21:17:55 | 1 | TCP:1 | 104.21.112.1 | 10.6.13.133 |
| 2025-06-13 21:18:25 | 2 | TCP:2 | 10.6.13.3, 20.190.157.14 | 10.6.13.133 |
| 2025-06-13 21:18:55 | 1 | TCP:1 | 104.21.112.1 | 10.6.13.133 |
| 2025-06-13 21:19:45 | 1 | TCP:1 | 104.21.112.1 | 10.6.13.133 |
| 2025-06-13 21:19:55 | 2 | TCP:2 | 10.6.13.133 | 104.21.112.1 |
| 2025-06-13 21:20:15 | 1 | TCP:1 | 104.21.112.1 | 10.6.13.133 |
| 2025-06-13 21:20:25 | 1 | TCP:1 | 104.21.80.1 | 10.6.13.133 |
| 2025-06-13 21:20:55 | 1 | TCP:1 | 10.6.13.133 | 104.16.231.132 |
| 2025-06-13 21:21:25 | 1 | TCP:1 | 10.6.13.133 | 104.21.80.1 |
| 2025-06-13 21:22:25 | 1 | TCP:1 | 10.6.13.133 | 104.21.80.1 |
| 2025-06-13 21:22:55 | 1 | TCP:1 | 10.6.13.133 | 104.21.80.1 |
| 2025-06-13 21:23:25 | 1 | TCP:1 | 10.6.13.133 | 104.21.80.1 |
| 2025-06-13 21:24:25 | 1 | TCP:1 | 104.16.231.132 | 10.6.13.133 |

## Recommended Actions
- [ ] Block outbound traffic to flagged IPs and domains at perimeter firewall
- [ ] Isolate host(s) initiating connections on suspicious ports
- [ ] Reset exposed user credentials
- [ ] Review internal logs for additional connections to suspicious domains
- [ ] Enforce TLS for all services handling credentials

## Indicators of Compromise (IOCs)
```text
wpad.massfriction.com
edge.microsoft.com
www.bing.com
windows-msgas.com
varying-rentals-calgary-predict.trycloudflare.com
event-datamicrosoft.live
www.google.com
s.clarity.ms
login.microsoftonline.com
config.edge.skype.com
event-datamicrosoft.live
varying-rentals-calgary-predict.trycloudflare.com
windows-msgas.com
ctldl.windowsupdate.com
www.msftconnecttest.com
event-time-microsoft.org
eventdata-microsoft.live
acroipm2.adobe.com
```