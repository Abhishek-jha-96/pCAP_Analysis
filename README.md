# pCAP_Analysis

## Setup Instructions

### Prerequisites
- Python 3.12
- Network Packet capture file.

### Instructions
Optional. (but recommened)
Create Virtual environment:

```bash
python3.12 -m venv <env_name>
```
active the environment with command:
(for linux)

```bash
source venv/bin/activate
```
Install required packages.

```bash
pip install -r requirements.txt
```
Place the data `.pcap` file at root level of the directory.

## Config file
create a file `config.ini`:
```bash
[DEFAULT]
API_KEY = AbuseIPDB_API_KEY
confidenceScore = 50 # Change this score.
maxAgeInDays = 30
```

Command to Run the script:

```bash
python main.py <file_name.pcap>
```
To generate report.md from the script:
```bash
python main.py <file_name.pcap> --md <report_filename.md>
```
To get a verbose output:
```bash
python main.py <file_name.pcap> --md <report_filename.md> --verbose
```