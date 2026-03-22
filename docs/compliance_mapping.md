# Compliance Mapping — HIPAA + NIST Reference

Complete mapping of HIPAA Security Rule sections and NIST SP 800-53 
controls used in this project for each alert type.

---

## Complete mapping table

| Use Case | HIPAA Rule | NIST Control | What is violated |
|----------|-----------|--------------|-----------------|
| Brute Force | §164.312(d) | AC-7 | Authentication controls + account lockout |
| Brute Force | §164.308(a)(5)(ii)(C) | IA-5 | Login monitoring + password management |
| Malware | §164.308(a)(1)(ii)(A) | SI-3 | Risk analysis + malware protection |
| Malware | §164.308(a)(5)(ii)(B) | IR-4 | Malicious software protection + incident response |
| Privilege Escalation | §164.312(a)(1) | AC-6 | Access control + least privilege |
| Privilege Escalation | §164.308(a)(3) | AC-2 | Workforce access management + account management |
| SQL Injection | §164.312(a)(2)(iv) | SI-10 | Database encryption + input validation |
| SQL Injection | §164.308(a)(1)(ii)(A) | SA-11 | Risk analysis + security testing |
| Generic (any) | §164.308(a)(1) | IR-4 | Security management process + incident handling |

---

## HIPAA rules explained

### §164.312(d) — Person/Entity Authentication
You must verify that whoever is trying to access patient data is who they claim to be.
Applies to: Brute Force — repeated failed logins indicate authentication bypass attempts.

### §164.308(a)(5)(ii)(C) — Log-in Monitoring
You must monitor login attempts and report suspicious patterns.
Applies to: Brute Force — detecting repeated failures is the direct implementation of this rule.

### §164.308(a)(1)(ii)(A) — Risk Analysis
You must regularly assess risks to patient data including malware and web vulnerabilities.
Applies to: Malware, SQL Injection.

### §164.308(a)(5)(ii)(B) — Protection from Malicious Software
You must have procedures to guard against, detect, and report malicious software.
Applies to: Malware — direct legal requirement fulfilled by the malware detection workflow.

### §164.312(a)(1) — Access Control
Every user must have a unique ID and only access what they need for their role.
Applies to: Privilege Escalation — a nurse account with root access violates this directly.

### §164.308(a)(3) — Workforce Access Management
You must have policies authorizing who can access what and supervise that access.
Applies to: Privilege Escalation — sudo rights on a clinician account = policy failure.

### §164.312(a)(2)(iv) — Encryption and Decryption
ePHI stored in databases must be encrypted.
Applies to: SQL Injection — successful injection risks exposing unencrypted patient records.

---

## NIST SP 800-53 controls explained

### AC-7 — Unsuccessful Logon Attempts
After a defined number of failed attempts, automatically lock the account.
Applies to: Brute Force — 47 failed attempts without lockout = AC-7 not enforced.

### IA-5 — Authenticator Management
Enforce password complexity, rotation, and revocation.
Applies to: Brute Force — weak passwords make brute force succeed.

### SI-3 — Malicious Code Protection
Deploy anti-malware at entry/exit points. Alert on detection and take defined action.
Applies to: Malware — the FIM alert is the SI-3 detection mechanism.

### IR-4 — Incident Handling
Have a defined process: preparation → detection → analysis → containment → recovery.
Applies to: Malware, Generic — any serious incident requires IR-4 activation.

### AC-6 — Least Privilege
Users should only have the minimum access required for their job.
Applies to: Privilege Escalation — nurse with root access = direct AC-6 violation.

### AC-2 — Account Management
Manage all accounts based on role. Review privileges regularly.
Applies to: Privilege Escalation — nurse account getting sudo rights = AC-2 failure.

### SI-10 — Information Input Validation
Reject invalid or malicious inputs at application entry points.
Applies to: SQL Injection — the attack succeeds when input validation is missing.

### SA-11 — Developer Security Testing
Require security testing including SQL injection detection during development.
Applies to: SQL Injection — vulnerable endpoint = SA-11 not implemented.
