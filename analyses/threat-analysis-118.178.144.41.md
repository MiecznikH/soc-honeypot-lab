# Threat Analysis: Silent Credential Harvester
**Attacker IP:** 118.178.144.41  
**Date:** 2026-06-02  
**Source:** China (CN) — Alibaba Cloud Data Center  
**AbuseIPDB Score:** 100% malicious confidence, 38 prior reports  

---

## Attack Summary

A credential harvesting bot originating from an Alibaba Cloud server in China
achieved a successful login to the honeypot using the credentials `root/AhSIjzPubO`.
Unlike the El Salvador brute force campaign, this attacker made no noise —
a single successful login, no commands executed, immediate disconnect.

This is a credential validation pattern: the tool confirms working credentials
exist and exits cleanly, leaving no trace of post-exploitation activity.
The credentials are likely logged for a second-wave attack at a later time.

---

## Attack Behaviour

### Phase 1 — Initial Access (T1110.001 - Brute Force: Password Guessing)
The attacker attempted authentication with a small set of credentials before
finding a working pair. The successful credential was `root/AhSIjzPubO` —
a non-trivial password suggesting the attacker is using a breach compilation
rather than a simple dictionary.

### Phase 2 — Reconnaissance (not observed)
After a successful login the attacker executed zero commands and disconnected
within milliseconds. This is deliberate — the tool is designed to validate
credentials silently without triggering behavioural detection systems.

### Phase 3 — Expected Next Steps (not observed — attacker blocked)
Based on the attack pattern, the expected follow-up would be:
- Return with a separate tool using the harvested credentials
- **T1083** — File and Directory Discovery
- **T1105** — Ingress Tool Transfer (malware download)
- **T1496** — Resource Hijacking (likely cryptominer based on Alibaba Cloud origin)

The attacker IP was automatically blocked by the Lambda auto-response pipeline
immediately after the successful login was detected.

---

## Comparison with Previous Attack (200.31.165.230)

| Property | 200.31.165.230 (SV) | 118.178.144.41 (CN) |
|---|---|---|
| Attack type | Brute force | Credential validation |
| Login attempts | 300+ | Few |
| Commands run | 1 (`echo ok`) | 0 |
| Noise level | High | Silent |
| Infrastructure | Fixed line ISP (likely compromised host) | Cloud VM (rented) |
| Wordlist | Leaked social media credentials | Breach compilation |
| Intent | Automated botnet expansion | Quiet credential harvesting |

Two different TTPs, same goal — finding working SSH credentials at scale.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Observed |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | ✅ Yes |
| T1078 | Valid Accounts | ✅ Yes (successful login) |
| T1083 | File and Directory Discovery | ❌ Blocked before execution |
| T1105 | Ingress Tool Transfer | ❌ Blocked before execution |
| T1496 | Resource Hijacking | ❌ Blocked before execution |

---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| IP Address | 118.178.144.41 |
| ASN | Aliyun Computing Co., LTD |
| Successful credential | root / AhSIjzPubO |

---

## Automated Response

The Lambda auto-block pipeline detected the attacker via Wazuh alert rule
100101 (cowrie.login.success, level 8) and automatically added a DENY rule
to the AWS Network ACL within seconds of the successful login.

---

## Threat Intelligence Enrichment

AbuseIPDB lookup performed automatically at time of block:
- **Country:** China (CN)
- **ISP:** Aliyun Computing Co., LTD (Alibaba Cloud)
- **Usage Type:** Data Center / Web Hosting / Transit
- **Abuse Confidence:** 100%
- **Prior Reports:** 38
- **Assessment:** Dedicated attack infrastructure. Alibaba Cloud VMs are
  commonly rented by threat actors for scanning and credential harvesting
  operations due to low cost and minimal abuse controls.
