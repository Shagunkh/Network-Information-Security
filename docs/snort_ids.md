# Snort-Based Real-Time Intrusion Detection System

This project blueprint implements a practical IDS pipeline using **Snort** for detecting:

- SQL Injection attempts
- Port scanning behavior
- DDoS-style bursts
- Brute-force login patterns

## 1. Architecture

```text
[Ingress/Egress Traffic]
          |
       [SPAN/TAP]
          |
   [Snort IDS Sensor]
          |
   [alert_fast / JSON / Unified2]
          |
   +---------------------------+
   |                           |
[Local analysis script]   [ELK Stack (optional)]
   |                           |
[Attack pattern report]   [Dashboards + alerts]
```

## 2. Snort Setup (quick start)

1. Install Snort 2.x or 3.x according to your distribution.
2. Copy custom rules from `snort/local.rules` into your local rules include path.
3. Ensure your `snort.conf` includes local rules, for example:

```conf
include $RULE_PATH/local.rules
```

4. Tune network variables in `snort.conf`:

```conf
ipvar HOME_NET 192.168.1.0/24
ipvar EXTERNAL_NET any
var RULE_PATH /etc/snort/rules
```

5. Validate configuration:

```bash
snort -T -c /etc/snort/snort.conf
```

6. Run Snort in IDS mode:

```bash
sudo snort -i eth0 -A fast -q -c /etc/snort/snort.conf -l /var/log/snort
```

## 3. Detection Logic

### SQL Injection
- Keyword and pattern-based signatures target common payload forms like `' OR 1=1 --` and `UNION SELECT`.
- Classed as `web-application-attack` for easy filtering.

### Port Scanning
- SYN packet bursts from a single source over short windows trigger reconnaissance alerts.

### DDoS Attempt
- High SYN rates toward a single destination in small windows trigger DoS-style alerts.

### Brute-Force Login
- Repeated requests to login endpoints from one source trigger brute-force alerts.

## 4. Attack Pattern Analysis

Use the included script to summarize `alert` logs:

```bash
python3 scripts/analyze_alerts.py --file /var/log/snort/alert
```

It reports:
- Top alert messages
- Classification distribution
- Priority distribution
- Top source and destination IPs

## 5. Optional ELK Integration

A practical stack for visualization:

- Filebeat/Logstash ingests Snort alerts
- Elasticsearch stores indexed events
- Kibana dashboards visualize trends

Suggested dashboards:
- Alerts over time (stacked by classification)
- Top talkers (source IP)
- Rule SID hit-rate
- High-priority incident panel

## 6. Compare Detection Rates (Custom vs Default Rules)

Method:
1. Replay same traffic sample with only default rules.
2. Replay with default + `local.rules`.
3. Compare:
   - True positives
   - False positives
   - Detection latency
   - Coverage per attack family

Suggested table format:

| Attack Type | Default Rules Detected | Custom Rules Detected | Improvement |
|-------------|-------------------------|-----------------------|-------------|
| SQLi        | 12/20                   | 18/20                 | +30%        |
| Scan        | 15/20                   | 19/20                 | +20%        |
| DDoS burst  | 10/20                   | 17/20                 | +35%        |
| Brute force | 9/20                    | 16/20                 | +35%        |

## 7. Notes

- Threshold values should be tuned per network baseline to avoid false positives.
- Start in alert-only mode before adding any blocking/IPS action.
- Keep local rule SID values unique and documented.
