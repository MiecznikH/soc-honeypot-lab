# SOC Honeypot Lab

A production-grade SSH honeypot deployed on AWS, feeding real-world attack data into a SIEM pipeline with automated threat response. Built to capture, analyse, and automatically block live attackers.

**Live since:** 2026-05-31 | **Sensors:** 2 (us-east-1, us-west-1) | **Attacks captured:** 1000+

---

## What This Does

Attackers on the internet constantly scan for exposed SSH servers. This lab lets them connect to a convincing fake Linux server, logs everything they do, enriches their IP with threat intelligence, and automatically blocks them — all without human intervention.

---

## Architecture

```
Internet
    │
    ▼
EC2 t3.micro (us-east-1)          EC2 t3.micro (us-west-1)
Cowrie SSH Honeypot                Cowrie SSH Honeypot
Port 2222                          Port 2222
    │                                   │
    └──────────── Wazuh Agent ──────────┘
                        │
                        ▼
            EC2 m7i-flex.large (us-east-1)
            Wazuh 4.11.2 Manager + OpenSearch
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
    Grafana Dashboard      AWS Lambda
    (attack visualisation) (auto-block pipeline)
                                  │
                            AbuseIPDB API
                            (threat intel)
                                  │
                            AWS Network ACL
                            (IP block rule)
```

---

## Stack

| Component | Technology |
|---|---|
| Honeypot | Cowrie 3.0 SSH Honeypot |
| Infrastructure | AWS EC2 (Ubuntu 22.04), 2 regions |
| SIEM | Wazuh 4.11.2 + OpenSearch |
| Visualisation | Grafana |
| Auto-response | AWS Lambda (Python) |
| Threat Intelligence | AbuseIPDB API |
| Network blocking | AWS Network ACL |

---

## Features

**Deception layer** — Cowrie presents attackers with a convincing fake Linux filesystem including a realistic bash history, fake environment files with AWS credentials, and deployment scripts designed to make the server look like a production environment.

**Automated blocking** — When an attacker triggers a Wazuh alert (level 6+), a Lambda function fires within seconds, queries AbuseIPDB for threat intelligence, and adds a DENY rule to the Network ACL. No human intervention required.

**Multi-sensor coverage** — Two honeypot sensors in different AWS regions (us-east-1 and us-west-1) provide broader geographic coverage and allow comparison of attack patterns across regions.

**MITRE ATT&CK mapping** — Custom Wazuh rules map Cowrie events to ATT&CK techniques (T1110 Brute Force, T1078 Valid Accounts, T1190 Exploit Public-Facing Application).

---

## Threat Intelligence Feed (sample)

| Date | IP | Country | Abuse Score | ISP | Technique |
|---|---|---|---|---|---|
| 2026-06-01 | 200.31.165.230 | SV | 37% | El Salvador Network | Brute Force + Shell beacon |
| 2026-06-02 | 118.178.144.41 | CN | 100% | Alibaba Cloud | Silent credential harvest |
| 2026-06-02 | 8.138.219.65 | CN | 100% | Aliyun Computing | Credential stuffing |
| 2026-06-02 | 20.221.56.85 | US | 100% | Microsoft Corporation | Automated scanning |
| 2026-06-02 | 47.84.140.213 | SG | 100% | Alibaba Cloud | Credential stuffing |

---

## Threat Analysis Reports

Detailed per-attacker analysis including TTPs, MITRE mapping, IOCs, and automated response logs:

- [200.31.165.230 — El Salvador credential stuffing bot](threat-analysis-200.31.165.230.md)
- [118.178.144.41 — Chinese silent credential harvester](threat-analysis-118.178.144.41.md)

---

## Wazuh Detection Rules

Custom rules at `/var/ossec/etc/rules/cowrie-rules.xml`:

```xml
<group name="cowrie,">
  <rule id="100100" level="6">
    <field name="eventid">cowrie.session.connect</field>
    <description>Cowrie: New connection from $(src_ip)</description>
    <mitre><id>T1190</id></mitre>
  </rule>
  <rule id="100101" level="8">
    <field name="eventid">cowrie.login.success</field>
    <description>Cowrie: Successful login from $(src_ip)</description>
    <mitre><id>T1078</id></mitre>
  </rule>
  <rule id="100102" level="6">
    <field name="eventid">cowrie.login.failed</field>
    <description>Cowrie: Failed login from $(src_ip)</description>
    <mitre><id>T1110</id></mitre>
  </rule>
</group>
```

---

## Grafana Dashboard

6 panels showing live attack data:

- Attack count over time
- Top 10 attacker IPs
- MITRE ATT&CK tactics (pie chart)
- Top attempted usernames
- Country of attack origin
- Attacks by sensor (us-east-1 vs us-west-1)
- Threat intelligence feed (CloudWatch)

---

## Project Status

- ✅ Cowrie honeypot live — 2 sensors (us-east-1, us-west-1)
- ✅ Wazuh SIEM ingesting Cowrie logs with custom decoder and rules
- ✅ MITRE ATT&CK mapping on all alert types
- ✅ Lambda auto-block pipeline — Cowrie → Wazuh → Lambda → NACL
- ✅ AbuseIPDB threat intelligence enrichment on every blocked IP
- ✅ Grafana dashboard with 6 panels including CloudWatch threat intel feed
- ✅ Honeyfs deception layer — fake credentials, bash history, deployment scripts
- ✅ 2 threat analysis reports from real captured attacks
- 🔄 Attacker behaviour analysis pipeline (in progress)
- 🔄 Active deception — canary tokens (planned)
