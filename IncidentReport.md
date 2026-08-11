# Incident Report — Automated SSH Credential-Stuffing Attack

**Analyst:** [Your Name]
**Date of Investigation:** August 10, 2026
**Source System:** Cowrie SSH Honeypot (`cowrie-honeypot`, Azure Qatar Central)
**Classification:** Automated Attack — Credential Stuffing / Brute Force
**Severity:** Low (honeypot environment, no production impact)
**Status:** Closed — No action required (expected honeypot activity)

---

## 1. Summary

Between 2026-08-10 01:07:04 UTC and 01:11:14 UTC, the SSH honeypot (Cowrie) running on `cowrie-honeypot` (public IP `48.217.234.93`) received a sustained series of automated login attempts from a single source IP, `193.32.162.27`. The activity pattern — rapid, sequential connections using a Go-based SSH client, cycling through common weak credential pairs, immediately followed by an automated system-fingerprinting script on every successful "login" — is consistent with a known botnet-driven SSH credential-stuffing campaign rather than a targeted, human-operated intrusion attempt.

## 2. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Source IP | `193.32.162.27` |
| SSH Client Version | `SSH-2.0-Go` |
| HASSH Fingerprint | `2ec37a7cc8daf20b10e1ad6221061ca5` |
| Destination | `10.0.0.4:2223` (internally redirected from public port 22) |
| Sessions observed | 5 distinct sessions in a 4-minute window |

## 3. Credentials Attempted

| Username | Password | Result |
|---|---|---|
| admin | adminroot | Accepted (honeypot) |
| admin | adminadmin | Accepted (honeypot) |
| user | user | Accepted (honeypot) |
| user | password | Accepted (honeypot) |
| user | 123456 | Accepted (honeypot) |
| user | guest | Accepted (honeypot) |
| user | User123 | Accepted (honeypot) |
| user | user@123 | Accepted (honeypot) |

All attempts used common, low-complexity username/password pairs consistent with a default credential wordlist rather than credentials specific to this host — no evidence of prior reconnaissance or targeting.

## 4. Post-Access Behavior

Immediately after each successful "login," the same automated command block executed on every session:

```
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
uname=$(uname -s -v -n -m ...)
arch=$(uname -m ...)
uptime=$(cat /proc/uptime ...)
cpus=$(nproc ...)
cpu_model=$(...)
gpu_info=$(lspci ... | grep -i vga/nvidia)
last_output=$(last ...)
```

This is a **system fingerprinting / environment reconnaissance script**, commonly used by botnet malware to determine:
- Whether the compromised host is a real server, VM, or container/sandbox
- CPU architecture and core count (for cryptomining or further payload suitability)
- Whether other users are logged in (`last` command — checking for legitimate admin activity)

No follow-on payload download, persistence mechanism, or lateral movement attempt was observed. The bot disconnected after fingerprinting completed (session durations: 9–13 seconds).

## 5. Timeline

| Time (UTC) | Event |
|---|---|
| 01:07:04 | Initial connection from 193.32.162.27 |
| 01:07:05 | Login accepted: `admin` / `adminroot` |
| 01:07:05 | Fingerprinting script executed |
| 01:07:14 | Session closed (9.0s duration) |
| 01:08:04 | New connection, second credential pair tested |
| 01:08:05 | Login accepted: `admin` / `adminadmin` |
| 01:08:16 | Session closed |
| 01:09:06 – 01:11:14 | Pattern repeats 3 additional times with new credential pairs |

## 6. Attribution / Context

A separate, earlier attacker against the same honeypot infrastructure (RDP service, IP `194.165.16.164`) was traced to **Flyservers S.A.**, a commercial hosting/VPS provider registered under RIPE with infrastructure geolocated to Lithuania. This is a common pattern: attackers rent inexpensive VPS instances specifically to run scanning and credential-stuffing tools, rather than exposing their real originating infrastructure. The SSH attacker in this report (`193.32.162.27`) follows the same general behavioral profile — automated tooling launched from third-party hosting infrastructure, not a residential or clearly attributable endpoint.

## 7. Assessment

This activity represents **routine, non-targeted internet background scanning**, not a directed attack against this organization or individual. The behavior — credential wordlist cycling, immediate automated fingerprinting, no persistence, short session duration — is consistent with well-documented SSH brute-force botnet behavior observed broadly across internet-exposed SSH services.

## 8. Recommended Actions (Production Context)

Had this been a production system rather than an intentional honeypot:

1. Block source IP `193.32.162.27` at the perimeter firewall.
2. Enforce SSH key-based authentication only; disable password authentication.
3. Enable fail2ban or equivalent to auto-block IPs after N failed attempts.
4. Move SSH off the default port 22 to reduce automated scanner exposure (defense-in-depth only — not a substitute for proper auth controls).
5. Alert on the specific fingerprinting command pattern (`uname -s -v -n -m` combined with `/proc/cpuinfo` and `lspci` greps in a single input line) as a higher-fidelity detection signature than login attempts alone.

## 9. Disposition

No further action required. This host is an intentional, isolated honeypot with no production data, credentials, or network access. Activity logged for research and detection-engineering purposes only.
