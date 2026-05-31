# SOC Honeypot Lab
AWS-EC2-hosted Cowrie SSH honeypot feeding into a SIEM pipeline.
Logs real-world attack data for threat analysis and detection engineering.

## Stack
- Cowrie 3.0 (SSH Honeypot)
- AWS EC2 (Ubuntu 26.04)
- Wazuh SIEM (Phase 2)
- Grafana Dashboard (Phase 3)
- AWS Lambda auto-response (Phase 4)

## Status
- ✅ Phase 1 - Cowrie honeypot live on AWS EC2
- ✅ Phase 2 - Wazuh SIEM connected, ingesting Cowrie logs
- MITRE ATT&CK mapping active
- ✅ Phase 3 - Grafana dashboard live with 4 panels
  - Attack timeline, Top attacker IPs, MITRE ATT&CK tactics, Top attempted usernames

