# SOC Honeypot Lab
AWS-EC2-hosted Cowrie SSH honeypot feeding into a SIEM pipeline.
Logs real-world attack data for threat analysis and detection engineering.

## Stack
- Cowrie 3.0 (SSH Honeypot)
- AWS EC2 (Ubuntu 26.04)
- Wazuh SIEM (Phase 2)
- Grafana Dashboard (Phase 3)
- AWS Lambda auto-response (Phase 4)

## Architecture
- Cowrie honeypot (EC2 t3.micro) → JSON logs → Wazuh agent
- Wazuh manager (EC2 m7i-flex.large) → parses alerts → triggers Lambda
- Lambda function → adds attacker IP to Network ACL deny rules
- Grafana dashboard → visualizes attack data from OpenSearch


## Status
- ✅ Phase 1 - Cowrie honeypot live on AWS EC2
- ✅ Phase 2 - Wazuh SIEM connected, ingesting Cowrie logs
- MITRE ATT&CK mapping active
- ✅ Phase 3 - Grafana dashboard live with 4 panels
  - Attack timeline, Top attacker IPs, MITRE ATT&CK tactics, Top attempted username
- ✅ Phase 4 - AWS Lambda auto-block pipeline complete
  - Custom Wazuh decoder and rules for Cowrie logs
  - Lambda function blocks attacking IPs in Network ACL automatically
  - Full pipeline: Cowrie → Wazuh → Lambda → NACL blocks
- ✅ Phase 5 - Added honeyfs deception layer with fake credentials and bash history
