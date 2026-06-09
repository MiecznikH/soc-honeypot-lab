# Threat Analysis: Large-Scale Credential Stuffing from Google Cloud
**Attacker IP:** 136.113.34.125  
**Date:** 2026-06-07  
**Duration:** ~1 hour sustained burst  
**Total events:** 63,672  
**Login attempts:** 7,958  
**Source:** Google LLC (GCP), United States  
**AbuseIPDB Score:** 77% malicious confidence, 52 prior reports  
**Last reported:** 2026-06-09 (active threat)  
**Sensor:** cowrie-honeypot-west (eu-west-1)  

---

## Attack Summary

A Google Cloud-hosted machine conducted the largest single-source attack 
observed across both honeypot sensors to date. Over 24 hours, the attacker 
maintained a sustained rate of approximately one connection every 11 seconds, 
cycling through a credential wordlist of ~8,000 password combinations targeting 
the root account exclusively.

---

## Threat Actor Attribution

### HASSH Fingerprint Correlation
The attacking client presented HASSH fingerprint 
`01ca35584ad5a1b66cf6a9846b5b2821` — **identical** to the El Salvador 
credential stuffing campaign documented on 2026-06-01 (see 
threat-analysis-200.31.165.230.md).

This cross-sensor, cross-campaign fingerprint match is high-confidence 
evidence that both attacks originate from the same malware kit or botnet 
operator, despite using different source IPs across different countries and 
a 6-day gap between campaigns.

| Attribute | Jun 1 Campaign | Jun 7 Campaign |
|---|---|---|
| Source IP | 200.31.165.230 | 136.113.34.125
|
| Country | El Salvador | United States (GCP) |
| HASSH | 01ca35584ad5a1b66cf6a9846b5b2821 | 01ca35584ad5a1b66cf6a9846b5b2821 |
| SSH Client | SSH-2.0-Go | SSH-2.0-Go / GET / HTTP/1.1 |
| Beacon command | echo -e "\x6F\x6B" | echo -e "\x6F\x6B" 
|
| Attempts | ~300 | 7,958 |
| Sensor | cowrie-honeypot (us-east-1) | cowrie-honeypot-west (eu-west-1) |

The scale difference (300 vs 7,958 attempts) suggests the operator escalated 
from a test run to a full campaign, or the GCP instance had significantly more 
resources available.

---

## Attack Behaviour

### Phase 1 — Initial Access (T1110.001 - Brute Force: Password Guessing)
7,958 unique credential pairs attempted within approximately 1 hour at 
~17 connections per second. This is an aggressive high-speed flood with 
no attempt at throttling or evasion — the attacker prioritised speed over 
stealth, exhausting their wordlist in under 30 minutes then continuing 
to hammer the port.

### Phase 2 — Execution (T1059 - Command and Scripting Interpreter)
Every successful login immediately executed:
```bash
echo -e "\x6F\x6B"
```
Identical beacon to the June 1st campaign. Shell responsiveness confirmed, 
session logged as viable, operator notified for second-wave payload delivery.

### Phase 3 — Infrastructure Choice (T1583.006 - Acquire Infrastructure: Web Services)
The attacker used Google Cloud Platform infrastructure rather than a 
compromised residential machine. This represents a deliberate operational 
security choice — cloud IPs carry implicit legitimacy, are less likely to be 
geo-blocked, offer high bandwidth, and provide reliable uptime for sustained 
campaigns. The HTTP version string (`GET / HTTP/1.1`) suggests the machine 
was also running other scanning tools concurrently.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Observed |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | ✅ Yes |
| T1078 | Valid Accounts | ✅ Yes |
| T1059 | Command and Scripting Interpreter | ✅ Yes |
| T1583.006 | Acquire Infrastructure: Web Services | ✅ Yes (GCP) |
| T1036 | Masquerading
| ✅ Possible (HTTP string on SSH port) |

---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| IP Address | 136.113.34.125 |
| ASN | Google LLC (GCP) |
| HASSH Fingerprint | 01ca35584ad5a1b66cf6a9846b5b2821 |
| Shell beacon | `echo -e "\x6F\x6B"` |
| SSH Client | SSH-2.0-Go |

**Cross-campaign IOC:** HASSH `01ca35584ad5a1b66cf6a9846b5b2821` links this 
campaign to the El Salvador campaign (200.31.165.230) from 2026-06-01. 
Any future connection presenting this fingerprint should be treated as 
high-confidence malicious regardless of source IP or geography.

---

## Automated Response

Lambda auto-block pipeline added NACL deny rule for 136.113.34.125 upon 
first Wazuh alert. However, the attacker's 11-second interval meant 
approximately 7,958 attempts completed before or around the time of blocking.

At 17 connections per second, the entire 8,000-password wordlist was 
exhausted in under 30 minutes. The Lambda block fired but was unable to 
prevent the bulk of attempts given the attack velocity.

This highlights a potential improvement: trigger blocking on 
`cowrie.session.connect` (level 6) rather than `cowrie.login.success` 
(level 8) to block earlier in the attack chain.

---

## Threat Intelligence

AbuseIPDB enrichment performed automatically at time of block:
- **Country:** United States
- **ISP:** Google LLC
- **Usage Type:** Data Center/Web Hosting/Transit
- **Abuse Confidence:** 77%
- **Prior Reports:** 52 (last reported 2026-06-09 — active threat)
- **Assessment:** GCP instance used as attack infrastructure, likely 
  a compromised or maliciously created cloud VM. Reported to AbuseIPDB 
  by 52 independent sources confirming widespread malicious activity.

---

## Recommended Actions
1. **Report to Google:** abuse@google.com with this IP and timeframe
2. **Lower alert threshold:** trigger Lambda block on level 6 
   (cowrie.session.connect) not level 8 (cowrie.login.success)
3. **HASSH blocklist:** consider proactive blocking of HASSH 
   `01ca35584ad5a1b66cf6a9846b5b2821` across both sensors
