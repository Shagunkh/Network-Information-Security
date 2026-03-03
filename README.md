# Network-Information-Security

## Snort-Based Real-Time Intrusion Detection System

This repository now includes a complete starter blueprint for a Snort-powered IDS that detects:

- SQL Injection
- Port scanning
- DDoS burst patterns
- Brute-force login attacks

### Repository contents

- `docs/snort_ids.md`: Implementation guide, architecture, setup, ELK extension ideas, and detection-rate comparison framework.
- `snort/local.rules`: Custom Snort detection signatures for the four attack families.
- `scripts/analyze_alerts.py`: Alert summarizer for quick attack pattern analysis from Snort logs.

### Quick start

```bash
# 1) Validate Snort config (after adding rules)
snort -T -c /etc/snort/snort.conf

# 2) Run Snort in IDS mode
sudo snort -i eth0 -A fast -q -c /etc/snort/snort.conf -l /var/log/snort

# 3) Analyze generated alerts
python3 scripts/analyze_alerts.py --file /var/log/snort/alert
```

See `docs/snort_ids.md` for full details.
