# Honeypot Intelligence — IOCs & Threat Data

**Sensor Location:** ganasec own infra
**Collection Period:** 2026-05-03 to 2026-05-06 (72 hours)

## Summary

| Metric | Value |
|--------|-------|
| SSH Sessions | 3,453 |
| HTTP Exploit Attempts | 79 |
| Unique Attacker IPs | 105 |
| Campaigns Identified | 7 |
| CVEs Exploited | 4 |
| Malware Samples | 0 (recon-only) |

## Campaigns Observed

| # | Campaign | Severity | Report |
|---|----------|----------|--------|
| 1 | Solana Validator Brute-Force | HIGH | [Full Analysis](reports/01_SOLANA_VALIDATOR_BRUTEFORCE.md) |
| 2 | Next.js Prototype Pollution RCE | CRITICAL | [Full Analysis](reports/02_NEXTJS_PROTOTYPE_POLLUTION_RCE.md) |
| 3 | Apache Self-Replicating Worm | HIGH | [Full Analysis](reports/03_APACHE_SELFREP_WORM.md) |
| 4 | WordPress Exploitation Toolkit | MEDIUM | [Full Analysis](reports/04_WORDPRESS_EXPLOITATION_TOOLKIT.md) |
| 5 | .env/Git Credential Harvesting | LOW | [Full Analysis](reports/05_ENV_GIT_CREDENTIAL_HARVESTING.md) |
| 6 | Yii2 Debug Panel Scanning | MEDIUM | [Full Analysis](reports/06_YII2_DEBUG_PANEL_SCANNING.md) |
| 7 | GeoServer RCE Scanning | HIGH | [Full Analysis](reports/07_GEOSERVER_RCE_SCANNING.md) |

## IOC Files (CSV)

| File | Description |
|------|-------------|
| [iocs_network.csv](iocs_network.csv) | All attacker IPs with ASN, country, campaign, and threat level |
| [iocs_ssh_credentials.csv](iocs_ssh_credentials.csv) | Credential pairs used in brute-force (Solana/crypto focused) |
| [iocs_http_payloads.csv](iocs_http_payloads.csv) | HTTP exploit paths, methods, and payload signatures |
| [iocs_file_artifacts.csv](iocs_file_artifacts.csv) | File system artifacts left by attackers |
| [iocs_c2_infrastructure.csv](iocs_c2_infrastructure.csv) | Command and control servers identified |

## Usage

Import CSVs into your SIEM, threat intel platform, or firewall rules:

```bash
# Block all attacker IPs
awk -F',' 'NR>1 {print $1}' iocs_network.csv | sort -u > blocklist.txt

# Import to iptables
while read ip; do iptables -A INPUT -s "$ip" -j DROP; done < blocklist.txt
```

## Detection Rules

### Snort/Suricata
```
# Next.js Prototype Pollution
alert http any any -> any any (msg:"Next.js Server Actions Prototype Pollution"; content:"Next-Action"; http_header; content:"__proto__"; http_client_body; sid:2026050601; rev:1;)

# Apache Worm C2
alert http any any -> any any (msg:"Apache CVE-2021-41773 Worm C2 Contact"; content:"125.135.169.171"; http_client_body; content:"apache.selfrep"; http_client_body; sid:2026050603; rev:1;)
```

### SSH Key Detection
```bash
# Search for planted attacker SSH key
grep -r "rsa-key-20230629" /home/*/.ssh/ /root/.ssh/ 2>/dev/null
```

## License

This threat intelligence data is released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Attribution: D0rkerDevil (@D0rkerDevil)

## Contact

- GitHub: [@dorkerdevil](https://github.com/dorkerdevil)
