# Detection Rules — Splunk SPL

Formal writeups of the detection logic built during this project. Each rule includes purpose, SPL, expected output, and operational considerations — written in the format a SOC would use to document and hand off a detection to production.

---

## Rule 1: RDP Brute-Force Detection (Rate-Based)

**Rule ID:** DET-001
**Data Source:** `sourcetype="WinEventLog:Security"`
**MITRE ATT&CK:** T1110 (Brute Force), T1110.001 (Password Guessing)

**Purpose:**
Detect a single source IP generating an abnormally high volume of failed RDP logon attempts (EventCode 4625) within a short time window — a strong indicator of automated credential-stuffing tooling rather than human error or legitimate access issues.

**Logic:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| bucket span=1m _time
| stats count as attempts_per_min by Source_Network_Address _time
| where attempts_per_min > 20
```

**Threshold Rationale:**
20 failed attempts within a single minute from one source is far outside the range of plausible human error (a legitimate user mistyping a password a handful of times). This threshold can be tuned based on observed baseline traffic; in this project's dataset, confirmed attacker IPs generated logon attempts at approximately one every 1.7 seconds (~35/minute), comfortably clearing this bar.

**False Positive Considerations:**
- Shared NAT/proxy egress points (many legitimate users behind one public IP) could inflate counts — not applicable in this honeypot's isolated environment, but relevant if deployed in production.
- Automated vulnerability scanners run by the organization's own security team should be allow-listed by IP.

**Response Action:** Block source IP at firewall/NSG; correlate with any successful logon (EventCode 4624) from the same IP as a higher-severity escalation (see Rule 3).

---

## Rule 2: SSH Credential Harvest & Command Execution (Cowrie)

**Rule ID:** DET-002
**Data Source:** `sourcetype=cowrie`
**MITRE ATT&CK:** T1110 (Brute Force), T1059 (Command and Scripting Interpreter), T1082 (System Information Discovery)

**Purpose:**
Surface every credential pair an attacker attempted against the SSH honeypot, alongside any commands executed after a simulated successful login — providing full visibility into both the access attempt and post-access behavior in a single view.

**Logic:**
```spl
index=main sourcetype=cowrie eventid=cowrie.login.success
| spath
| eval src_ip=mvindex(src_ip, 0)
| stats count as attempts values(username) as usernames values(password) as passwords by src_ip
| sort - attempts
```

```spl
index=main sourcetype=cowrie eventid=cowrie.command.input
| spath
| eval src_ip=mvindex(src_ip, 0)
| table _time src_ip input
```

**Operational Note:**
Unlike Windows Security event logs, Cowrie is an application-layer honeypot and therefore legitimately captures cleartext credentials and full command input — this is by design for honeypot telemetry and would not be appropriate or expected from a production authentication system's logs.

**Response Action:** In production, any successful authentication event should immediately trigger review of subsequent command execution; the discovery-stage recon script pattern identified in this dataset (see Rule 3) is a useful higher-fidelity secondary signal.

---

## Rule 3: Automated Recon Script Detection (High-Fidelity)

**Rule ID:** DET-003
**Data Source:** `sourcetype=cowrie`
**MITRE ATT&CK:** T1082 (System Information Discovery), T1033 (System Owner/User Discovery)

**Purpose:**
Detect the specific automated fingerprinting command pattern observed across multiple unrelated attacker sessions in this dataset — a chained shell script collecting `uname`, CPU/GPU info, and logged-in user data immediately after login. This pattern is a stronger, more specific indicator of automated malicious tooling than a login event alone, since it reflects intent to profile the compromised host.

**Logic:**
```spl
index=main sourcetype=cowrie eventid=cowrie.command.input
| spath
| search input="*uname -s -v -n -m*" AND input="*lscpu*"
| table _time src_ip input
```

**Why This Matters:**
A login event only tells you an attempt occurred. This detection confirms the attacker's tooling actively took a next step — reconnaissance — which is a meaningfully higher-confidence signal for prioritization in a SOC queue than raw brute-force volume alone. In this project's data, this exact script signature appeared identically across multiple unrelated source IPs (`193.32.162.27`, `45.153.34.41`, and others), indicating a shared, widely distributed botnet toolkit rather than isolated custom activity.

**Response Action:** Treat as confirmed automated compromise attempt; any host reflecting this pattern with a real (non-honeypot) response should be treated as escalated priority for isolation and forensic review.

---

## Rule 4: Combined Cross-Honeypot Attacker Geography

**Rule ID:** DET-004 (Enrichment, not alerting)
**Data Source:** `sourcetype="WinEventLog:Security"` + `sourcetype=cowrie`
**MITRE ATT&CK:** T1590 (Gather Victim Network Information — supporting attribution context)

**Purpose:**
Correlate attacker geography across both honeypot surfaces (RDP + SSH) into a single enrichment view, supporting situational awareness of which regions/hosting providers are generating the most attack volume against the environment as a whole.

**Logic:**
```spl
(index=* sourcetype="WinEventLog:Security" EventCode=4625) OR (index=main sourcetype=cowrie eventid=cowrie.login.success)
| eval src_ip=coalesce(Source_Network_Address, mvindex(src_ip,0))
| iplocation src_ip
| eval Country=case(Country="Lithuania", "Republic of Lithuania", 1=1, Country)
| stats count as attacks by Country
| geom geo_countries featureIdField=Country
```

**Note:** This is an enrichment/visualization query rather than a standalone alert — it supports investigation and trend reporting rather than firing on a threshold. GeoIP data reflects the geographic location of hosting infrastructure, not necessarily the attacker's physical location, and should be treated as context rather than definitive attribution.
