# Architecture — SOC ML Recommendation Engine

## Overview

The ML engine is designed as a **parallel branch** inside an existing n8n SOAR pipeline.
The existing automated workflows remain completely unchanged.
The ML branch runs alongside them and adds compliance-aware recommendations to each case.

---

## Data flow
```
Wazuh Alert
     ↓
n8n SOAR Workflow
     ├── [EXISTING] Automated actions
     │         ↓
     │   Block IP on pfSense
     │   Isolate host
     │   Create TheHive case
     │
     └── [NEW] ML Recommendation Branch
               ↓
         ml_engine.py (Flask API)
               ↓
         Gemini 2.5 Flash
               ↓
         Structured recommendation
               ↓
         Added as note to TheHive case
```

The analyst opens **one TheHive case** and sees:
- Automated actions already taken
- ML recommendation with compliance mapping

---

## Components

| Component | Role | Location |
|-----------|------|----------|
| Wazuh Manager | Detects threats, generates alert JSON | SOC zone — 10.10.40.20 |
| n8n SOAR | Orchestrates workflows, calls ML engine | SOC zone — 10.10.40.50 |
| ML Engine | Analyzes alerts, calls Gemini | Colab (PoC) / local server (production) |
| Gemini 2.5 Flash | Generates recommendations | Google Cloud API |
| TheHive | Stores cases and recommendations | SOC zone — 10.10.40.40 |

---

## Alert processing timeline
```
T+0s   — Attack occurs on endpoint
T+1s   — Wazuh agent captures log event
T+2s   — Wazuh Manager matches rule, generates alert JSON
T+3s   — Webhook fires to n8n
T+4s   — n8n detects alert type, starts workflow
T+5s   — ML engine called with alert JSON
T+7s   — Prompt built with HIPAA + NIST compliance rules
T+9s   — Gemini returns structured recommendation
T+10s  — TheHive case created with recommendation note
T+11s  — SOC analyst sees complete analysis
```

---

## Alert type detection

The engine detects alert type from Wazuh's `rule.groups` field:

| Groups field contains | Detected as | Compliance injected |
|----------------------|-------------|-------------------|
| `brute_force` or `authentication_failures` | brute_force | HIPAA §164.312(d) + NIST AC-7 |
| `malware` or `syscheck` or `rootcheck` | malware | HIPAA §164.308(a)(5)(ii)(B) + NIST SI-3 |
| `privilege_escalation` or `sudo` | privilege_escalation | HIPAA §164.312(a)(1) + NIST AC-6 |
| `sql_injection` or `web` + `attack` | sql_injection | HIPAA §164.312(a)(2)(iv) + NIST SI-10 |
| anything else | generic | HIPAA §164.308(a)(1) + NIST IR-4 |

---

## Design decision — why parallel branch

The ML feature advises — it does not act. The automated response (block IP, isolate host) runs regardless of whether the ML engine is available. This means:

- If Gemini API is down — automated response still works
- If ML engine crashes — no impact on incident response
- The analyst always has automated containment — the ML recommendation is additional context

See [compliance_mapping.md](compliance_mapping.md) for the full HIPAA + NIST reference.
```

