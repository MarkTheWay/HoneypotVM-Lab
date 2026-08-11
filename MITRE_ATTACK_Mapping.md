# MITRE ATT&CK Mapping — Honeypot Observed Activity

This document maps behavior directly observed in the RDP and SSH honeypot logs (collected in Splunk) to the [MITRE ATT&CK](https://attack.mitre.org/) framework. Every technique listed below is backed by real log evidence from this project, not theoretical coverage.

| Technique ID | Technique Name | Tactic | Evidence Observed |
|---|---|---|---|
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access | Repeated failed RDP logon attempts (EventCode 4625) from `194.165.16.164` at ~1.7 second intervals cycling through usernames (`administrator`, `standard`, `intel`, `sans`, `leila`, `vinicius`, etc.). Repeated SSH login attempts against Cowrie from `193.32.162.27` cycling through common credential pairs. |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Credential Access | Sequential guessing of common/weak passwords (`123456`, `password`, `user`, `guest`, `User123`) observed in Cowrie `cowrie.login.success` events. |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Initial Access / Persistence | Cowrie is configured to accept a subset of credential attempts as "successful," simulating the initial-access outcome an attacker achieves after a successful brute-force — used here to observe attacker post-access behavior safely. |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | Discovery | Automated fingerprinting script executed on every successful Cowrie session, collecting `uname`, CPU architecture, core count, GPU info (`lspci`/`nvidia`), and uptime — consistent with attacker/malware reconnaissance of the compromised host prior to further action. |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Discovery | The recon script includes a `last` command, checking recently logged-in users — used to detect whether legitimate administrators are active on the host. |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution | Full shell command execution captured via Cowrie's `cowrie.command.input` events, including chained Bash logic with multiple fallback interpreters (`bash`, `/bin/bash`, `busybox sh`) to maximize compatibility across target environments. |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Unix Shell | Execution | Attacker-executed commands used standard POSIX shell syntax and `busybox` fallbacks, indicating tooling designed to run against a broad range of Linux/embedded targets. |
| [T1595](https://attack.mitre.org/techniques/T1595/) | Active Scanning | Reconnaissance | Initial port/service discovery inferred from the near-immediate connection to both honeypots after public exposure (RDP found within hours; SSH found within ~7 minutes of the port-22 redirect going live), consistent with continuous internet-wide scanning infrastructure. |
| [T1590](https://attack.mitre.org/techniques/T1590/) | Gather Victim Network Information | Reconnaissance | GeoIP/WHOIS analysis performed during this investigation identified the RDP attacker's origin IP as belonging to Flyservers S.A., a commercial hosting provider — consistent with attackers using rented infrastructure rather than exposing their own. |

## Notes on Scope

- This mapping reflects **attacker-observed** techniques only (what was captured hitting the honeypots), not defensive/mitigating techniques.
- No lateral movement, persistence installation, data exfiltration, or payload delivery was observed in this dataset — all captured sessions were consistent with automated scanning/credential-stuffing bots that disconnected after initial fingerforming, not sustained manual intrusions.
- Both honeypots (Windows RDP, Linux/Cowrie SSH) fed a shared Splunk indexer, allowing technique correlation across two different attack surfaces in a single view.
