# soc-ml-recommendation-engine


> An LLM-powered compliance-aware recommendation engine for SOC analysts.
> Analyzes Wazuh SIEM alerts, maps them to HIPAA and NIST frameworks, and generates actionable incident response recommendations in under 10 seconds.

[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://python.org)
[![Gemini](https://img.shields.io/badge/Gemini-2.5--flash-orange)](https://aistudio.google.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](notebooks/SOC_ML_Testing.ipynb)

---

## The problem

SOC analysts in healthcare environments receive hundreds of alerts daily. For each alert they must manually determine:
- What happened and how serious is it?
- Which HIPAA regulation or NIST control was violated?
- What should I do in the next 15 minutes?
- What do I write in the incident case?

This takes 5–15 minutes per alert. Alert fatigue is one of the top challenges in security operations.

---

## The solution

This engine receives a Wazuh alert JSON, automatically maps it to the relevant HIPAA and NIST compliance rules, and generates a structured recommendation for the analyst — in under 10 seconds.

```
Wazuh Alert (JSON)
       +
Compliance Rules (HIPAA + NIST)
       ↓
  Gemini 2.5 Flash
       ↓
SOC Analyst Recommendation
       ↓
  TheHive Case Note
```

---

## Sample output

**Input — Privilege Escalation alert from Wazuh:**
```json
{
  "rule": {"id": "5402", "level": 9, "groups": ["sudo", "privilege_escalation"]},
  "agent": {"name": "healthcare-linux-workstation", "ip": "10.10.20.51"},
  "data": {"srcuser": "nurse_account_12", "command": "sudo su -"}
}
```

**Output — Gemini recommendation:**
```
WHAT HAPPENED: Clinical account nurse_account_12 successfully escalated
to root at 22:07, outside normal working hours. A nurse account should
never have administrative access to a clinical workstation.

THREAT LEVEL: CRITICAL — Unauthorized root access on a machine handling
ePHI, indicating either a compromised account or a serious misconfiguration.

COMPLIANCE VIOLATION: HIPAA §164.312(a)(1) — clinician account exceeded
authorized access. NIST AC-6 (least privilege) directly violated.

IMMEDIATE ACTIONS:
1. Lock nurse_account_12 immediately
2. Terminate the active root session
3. Isolate the workstation from the network
4. Notify the incident response team

INVESTIGATION STEPS:
1. Check /etc/sudoers — how did this account get sudo rights?
2. Review bash history for commands run as root
3. Check login history for nurse_account_12 over the past 7 days
4. Verify no files were accessed or exfiltrated during root session

CASE NOTES FOR THEHIVE: CRITICAL — nurse_account_12 escalated to root
on healthcare-linux-workstation at 22:07 via sudo su -. HIPAA §164.312(a)(1)
and NIST AC-6 violated. Account locked, workstation isolated. Full
forensic investigation required.
```

---

## Use cases and compliance mapping

| Alert Type | HIPAA Rule | NIST Control | Severity |
|-----------|-----------|--------------|---------|
| SSH Brute Force | §164.312(d) + §164.308(a)(5)(ii)(C) | AC-7 + IA-5 | HIGH |
| Malware Detection | §164.308(a)(5)(ii)(B) + §164.308(a)(1)(ii)(A) | SI-3 + IR-4 | CRITICAL |
| Privilege Escalation | §164.312(a)(1) + §164.308(a)(3) | AC-6 + AC-2 | CRITICAL |

---

## Architecture

This engine is designed as a **parallel branch** inside an existing n8n SOAR pipeline:

```
Wazuh Alert
     ↓
n8n SOAR Workflow
     ├── [EXISTING] Automated actions (block IP, isolate host)
     │         ↓
     │   TheHive Case Created
     │
     └── [NEW] ML Recommendation Branch
               ↓
         This Engine (Flask API)
               ↓
         Gemini 2.5 Flash
               ↓
         Recommendation added to TheHive Case
```

The automated response runs unchanged. The ML branch adds compliance-aware context for the analyst. If the ML branch fails, the automated response still works independently.

---

## Tech stack

| Component | Tool |
|-----------|------|
| LLM | Google Gemini 2.5 Flash (free tier) |
| Runtime | Google Colab or local Python |
| SIEM | Wazuh (alert source) |
| SOAR | n8n (orchestration) |
| Case management | TheHive |
| Live integration | Flask + ngrok (PoC) |

---

## Project context

Built as the ML feature for a **Healthcare SOC/SOAR university project** implementing a full security operations center for a healthcare organization.

Full infrastructure stack: Wazuh + n8n + TheHive + Cortex + MISP + pfSense + Suricata + Zeek on Proxmox — 4 network zones (WAN, LAN, DMZ, SOC), 7-person team.

This repo contains only the ML recommendation engine component. The engine addresses an open feature request on the official Wazuh GitHub (August 2025) asking for exactly this capability — compliance-aware LLM analysis of security alerts.

---

## Quick start

### Option 1 — Google Colab (fastest, no setup)

1. Get a free Gemini API key at https://aistudio.google.com/
2. Click the Colab badge above
3. Add your key to Colab Secrets (key icon in sidebar) as `GEMINI_API_KEY`
4. Run all cells

### Option 2 — Local Python

```bash
git clone https://github.com/YOUR_USERNAME/soc-ml-recommendation-engine
cd soc-ml-recommendation-engine
pip install -r requirements.txt
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
python ml_engine.py
```

### Option 3 — Live integration with n8n (ngrok)

1. Run `notebooks/SOC_ML_ngrok.ipynb` in Colab
2. Copy the ngrok URL printed in output
3. Add an HTTP Request node in n8n pointing to `<ngrok-url>/recommend`
4. Send Wazuh alert JSON as the request body
5. Recommendation returns to n8n and gets added to TheHive case

---

## Repository structure

```
soc-ml-recommendation-engine/
├── README.md                        — This file
├── ml_engine.py                     — Production Flask server with token auth
├── requirements.txt                 — Python dependencies
├── .env.example                     — Environment variable template
├── .gitignore
│
├── notebooks/
│   ├── SOC_ML_Testing.ipynb         — Static testing (no server needed)
│   └── SOC_ML_ngrok.ipynb           — Live integration with n8n via ngrok
│
├── alerts/
│   ├── brute_force.json             — Sample Wazuh alert: SSH brute force
│   ├── malware.json                 — Sample Wazuh alert: malware detection
│   └── privilege_escalation.json   — Sample Wazuh alert: sudo to root
│
└── docs/
    ├── architecture.md              — Full data flow and component diagram
    └── compliance_mapping.md        — HIPAA + NIST reference table
```

---

## Security notes

- Never hardcode your API key in code — use environment variables or Colab Secrets
- The production server (`ml_engine.py`) requires a token header for all requests
- In production, use a self-hosted LLM (e.g. Llama 3) to keep alert data on-premises
- Simulated alerts are used in this PoC — no real patient data is processed

---

## License

MIT — free to use, modify, and distribute with attribution.
