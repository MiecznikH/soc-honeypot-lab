# Threat Analysis: Credential Stuffing Campaign
**Attacker IP:** 200.31.165.230  
**Date:** 2026-06-01  
**Duration:** ~3 minutes (10:09 - 10:12 UTC)  
**Total attempts:** 300+  
**Source:** El Salvador (SV) — Fixed Line ISP  
**AbuseIPDB Score:** 37% malicious confidence, 6 prior reports  

---

## Attack Summary

An automated credential stuffing bot originating from El Salvador conducted 
a high-speed brute force campaign against the honeypot's SSH service on port 
2222. The bot cycled through a pre-built wordlist at approximately one attempt 
every 300ms, targeting the root account exclusively.

---

## Attack Behaviour

### Phase 1 — Initial Access (T1110.001 - Brute Force: Password Guessing)
The bot established a new TCP connection for each credential pair rather than 
reusing sessions. This is characteristic of tools designed to evade 
rate-limiting and session-based lockout mechanisms.

Connection rate: ~3 attempts/second  
Target account: root (exclusively)  
Wordlist characteristics: leaked social media credentials (MySpace/Facebook era)  
Sample passwords attempted: `batman12`, `soccer18`, `jeffhardy1`, `houston713`, 
`jesussaves`, `puertorico`, `andrew2`

The wordlist is c# Threat Analysis: Credential Stuffing Campaign
**Attacker IP:** 200.31.165.230  
**Date:** 2026-06-01  
**Duration:** ~3 minutes (10:09 - 10:12 UTC)  
**Total attempts:** 300+  
**Source:** El Salvador (SV) — Fixed Line ISP  
**AbuseIPDB Score:** 37% malicious confidence, 6 prior reports  

---

## Attack Summary

An automated credential stuffing bot originating from El Salvador conducted 
a high-speed brute force campaign against the honeypot's SSH service on port 
2222. The bot cycled through a pre-built wordlist at approximately one attempt 
every 300ms, targeting the root account exclusively.

---

## Attack Behaviour

### Phase 1 — Initial Access (T1110.001 - Brute Force: Password Guessing)
The bot established a new TCP connection for each credential pair rather than 
reusing sessions. This is characteristic of tools designed to evade 
rate-limiting and session-based lockout mechanisms.

Connection rate: ~3 attempts/second  
Target account: root (exclusively)  
Wordlist characteristics: leaked social media credentials (MySpace/Facebook era)  
Sample passwords attempted: `batman12`, `soccer18`, `jeffhardy1`, `houston713`, 
`jesussaves`, `puertorico`, `andrew2`

The wordlist is consistent with large-scale breach compilations — passwords 
reflect real human choices rather than random generation, suggesting the 
attacker is using a database of previously compromised credentials.

### Phase 2 — Execution (T1059 - Command and Scripting Interpreter)
Upon each successful authentication, the bot immediately executed:
```bash
echo -e "\x6F\x6B"
```
This decodes to `ok` — a shell responsiveness check. The bot is confirming 
the honeypot shell is interactive before logging the session as a viable target.
This is inventory behaviour — the operator will review results and return with 
a payload in a second wave.

### Phase 3 — Expected Next Steps (not observed — attacker blocked)
Based on known botnet behaviour patterns, the expected follow-up would be:
- **T1083** — File and Directory Discovery (`ls`, `uname -a`, `cat /etc/passwd`)
- **T1105** — Ingress Tool Transfer (wget/curl to download malware)
- **T1496** — Resource Hijacking (cryptominer deployment)
- **T1021** — Remote Services (lateral movement to other discovered hosts)

The attacker was automatically blocked at the NACL level by the Lambda 
auto-response pipeline before Phase 3 could begin.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Observed |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | ✅ Yes |
| T1078 | Valid Accounts | ✅ Yes (honeypot accepted credentials) |
| T1059 | Command and Scripting Interpreter | ✅ Yes (`echo` command) |
| T1083 | File and Directory Discovery | ❌ Blocked before execution |
| T1105 | Ingress Tool Transfer | ❌ Blocked before execution |
| T1496 | Resource Hijacking | ❌ Blocked before execution |

---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| IP Address | 200.31.165.230 |
| ASN | El Salvador Network S.A. |
| SSH Client | SSH-2.0-Go |
| HASSH Fingerprint | 01ca35584ad5a1b66cf6a9846b5b2821 |
| Shell beacon | `echo -e "\x6F\x6B"` |

**HASSH fingerprint** is particularly valuable — this is a fingerprint of the 
SSH client's cipher preferences. Any future connection with HASSH 
`01ca35584ad5a1b66cf6a9846b5b2821` is almost certainly the same tool, 
regardless of source IP.

---

## Automated Response

The Lambda auto-block pipeline detected the attacker via Wazuh alert rule 
100101 (cowrie.login.success, level 8) and automatically added a DENY rule 
to the AWS Network ACL within seconds of the first successful login, 
terminating the attack mid-campaign.

---

## Threat Intelligence Enrichment

AbuseIPDB lookup performed automatically at time of block:
- **Country:** El Salvador (SV)
- **ISP:** El Salvador Network, S.A.
- **Usage Type:** Fixed Line ISP
- **Abuse Confidence:** 37%
- **Prior Reports:** 6 (last reported 2026-05-27)
- **Assessment:** Likely compromised residential/office machine used as 
  a proxy node in a larger botnet operation.
