"""
SOC ML Recommendation Engine
Healthcare-focused compliance-aware LLM recommendation engine for SOC analysts.
Analyzes Wazuh SIEM alerts and maps them to HIPAA and NIST frameworks.

Author: 0xdaxl
GitHub: https://github.com/0xdaxl/soc-ml-recommendation-engine
"""

from google import genai
from flask import Flask, request, jsonify
from functools import wraps
import os
import json
import threading

# ============================================================
# CONFIGURATION
# Load from environment variables — never hardcode
# ============================================================
API_KEY = os.environ.get("GEMINI_API_KEY")
API_TOKEN = os.environ.get("ML_API_TOKEN", "changeme")

if not API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable not set. See .env.example")

client = genai.Client(api_key=API_KEY)

# ============================================================
# COMPLIANCE RULES
# Maps each alert type to specific HIPAA + NIST controls
# To add a new alert type: add an entry here and in detect_alert_type()
# ============================================================
compliance_map = {
    "brute_force": """
HIPAA §164.312(d) — Person/Entity Authentication:
Implement procedures to verify that a person or entity seeking access
to ePHI is who they claim to be. Failed authentication must be monitored.

HIPAA §164.308(a)(5)(ii)(C) — Log-in Monitoring:
Procedures for monitoring log-in attempts and reporting discrepancies.

NIST AC-7 — Unsuccessful Logon Attempts:
Enforce a limit on consecutive invalid logon attempts. Lock the account
after the threshold is exceeded.

NIST IA-5 — Authenticator Management:
Manage system authenticators including passwords, tokens, and certificates.
    """,

    "malware": """
HIPAA §164.308(a)(1)(ii)(A) — Risk Analysis:
Conduct an accurate and thorough assessment of potential risks to ePHI.

HIPAA §164.308(a)(5)(ii)(B) — Protection from Malicious Software:
Procedures for guarding against, detecting, and reporting malicious software.

NIST SI-3 — Malicious Code Protection:
Implement malicious code protection at system entry/exit points.
Take action when malicious code is detected including alerting administrators.

NIST IR-4 — Incident Handling:
Implement an incident handling capability including preparation,
detection, analysis, containment, eradication, and recovery.
    """,

    "privilege_escalation": """
HIPAA §164.312(a)(1) — Access Control — Unique User Identification:
Assign a unique name/number for identifying and tracking user identity.
Clinician accounts must only have access required for their role.

HIPAA §164.308(a)(3) — Workforce Access Management:
Implement policies to authorize and supervise workforce access to ePHI.

NIST AC-6 — Least Privilege:
Employ the principle of least privilege, allowing only authorized access
required for users to accomplish assigned tasks.

NIST AC-2 — Account Management:
Manage system accounts including establishing, activating, and monitoring.
Immediately disable accounts when no longer required or authorized.
    """,

    "sql_injection": """
HIPAA §164.312(a)(2)(iv) — Encryption and Decryption:
Implement a mechanism to encrypt and decrypt ePHI stored in databases.

HIPAA §164.308(a)(1)(ii)(A) — Risk Analysis:
Web application vulnerabilities represent direct risks to ePHI stored
in backend databases. SQL injection must be included in risk assessments.

NIST SI-10 — Information Input Validation:
Check information for accuracy, completeness, validity, and authenticity.
Reject invalid inputs at application entry points.

NIST SA-11 — Developer Security Testing:
Require application security testing including SQL injection detection.
    """,

    "generic": """
HIPAA §164.308(a)(1) — Security Management Process:
Implement policies and procedures to prevent, detect, contain, and
correct security violations affecting ePHI.

NIST IR-4 — Incident Handling:
Implement an incident handling capability for security incidents
including preparation, detection, analysis, containment and recovery.

NIST SI-5 — Security Alerts and Advisories:
Receive information system security alerts and take appropriate actions
in response to detected threats.
    """
}

# ============================================================
# ALERT TYPE DETECTION
# Detects alert category from Wazuh rule groups field
# Add new elif blocks here to support additional alert types
# ============================================================
def detect_alert_type(alert):
    groups = alert.get("rule", {}).get("groups", [])
    description = alert.get("rule", {}).get("description", "").lower()

    if "brute_force" in groups or "authentication_failures" in groups:
        return "brute_force"
    elif "malware" in groups or "syscheck" in groups or "rootcheck" in groups:
        return "malware"
    elif "privilege_escalation" in groups or "sudo" in groups:
        return "privilege_escalation"
    elif "sql_injection" in groups or "web" in groups and "attack" in groups:
        return "sql_injection"
    else:
        return "generic"

# ============================================================
# PROMPT BUILDER
# Constructs the full prompt sent to Gemini
# System role + compliance context + alert data + output format
# ============================================================
def build_prompt(alert, alert_type):
    compliance = compliance_map[alert_type]
    alert_str = json.dumps(alert, indent=2)

    prompt = f"""You are an expert SOC analyst specializing in healthcare cybersecurity.
You have deep knowledge of HIPAA Security Rule (45 CFR Part 164) and NIST SP 800-53 controls.
You are analyzing alerts from a Wazuh SIEM deployed in a healthcare environment
that handles Electronic Health Records (EHR) and Protected Health Information (PHI).
Your job is to give clear, actionable recommendations to SOC analysts.

RELEVANT COMPLIANCE RULES FOR THIS ALERT TYPE:
{compliance}

WAZUH ALERT TO ANALYZE:
{alert_str}

Provide your analysis in EXACTLY this format — do not deviate:

**WHAT HAPPENED:** (2-3 sentences explaining the event in plain language)

**THREAT LEVEL:** (CRITICAL / HIGH / MEDIUM / LOW — one sentence justification)

**COMPLIANCE VIOLATION:** (Specific HIPAA section and NIST control violated and how)

**IMMEDIATE ACTIONS:** (Numbered list — what the analyst must do in the next 15 minutes)

**INVESTIGATION STEPS:** (Numbered list — what to check to understand full scope)

**CASE NOTES FOR THEHIVE:** (Short paragraph ready to paste into the incident case)
"""
    return prompt

# ============================================================
# RECOMMENDATION ENGINE
# Core function — takes any Wazuh alert JSON, returns recommendation
# ============================================================
def get_recommendation(alert):
    alert_type = detect_alert_type(alert)
    prompt = build_prompt(alert, alert_type)
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt
    )
    return response.text, alert_type

# ============================================================
# TOKEN AUTHENTICATION
# Protects the API endpoint — n8n must send the token in headers
# Header: X-API-Token: your_token_value
# ============================================================
def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-API-Token")
        if API_TOKEN != "changeme" and token != API_TOKEN:
            return jsonify({"error": "Unauthorized — invalid or missing token"}), 401
        return f(*args, **kwargs)
    return decorated

# ============================================================
# FLASK API SERVER
# Endpoints:
#   POST /recommend  — analyze a Wazuh alert
#   GET  /health     — check if engine is running
# ============================================================
app = Flask(__name__)

@app.route('/recommend', methods=['POST'])
@require_token
def recommend():
    alert = request.json

    if not alert:
        return jsonify({"error": "No alert data received — send Wazuh alert as JSON body"}), 400

    if "rule" not in alert:
        return jsonify({"error": "Invalid alert format — missing 'rule' field"}), 400

    rule_description = alert.get("rule", {}).get("description", "unknown")
    agent_name = alert.get("agent", {}).get("name", "unknown")
    level = alert.get("rule", {}).get("level", 0)

    print(f"\n[ALERT RECEIVED]")
    print(f"  Rule:   {rule_description}")
    print(f"  Agent:  {agent_name}")
    print(f"  Level:  {level}/15")

    recommendation, alert_type = get_recommendation(alert)

    print(f"  Type:   {alert_type}")
    print(f"[RECOMMENDATION SENT] {recommendation[:80]}...")

    return jsonify({
        "status": "success",
        "alert_type": alert_type,
        "agent": agent_name,
        "rule": rule_description,
        "severity_level": level,
        "recommendation": recommendation
    })


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ML engine running",
        "model": "gemini-2.5-flash",
        "supported_alert_types": list(compliance_map.keys())
    })


# ============================================================
# ENTRY POINT
# Run: python ml_engine.py
# ============================================================
if __name__ == '__main__':
    print("\n" + "="*60)
    print("SOC ML RECOMMENDATION ENGINE")
    print("="*60)
    print(f"Model:    gemini-2.5-flash")
    print(f"Endpoint: http://0.0.0.0:5000/recommend")
    print(f"Health:   http://0.0.0.0:5000/health")
    print(f"Auth:     {'enabled' if API_TOKEN != 'changeme' else 'disabled (set ML_API_TOKEN)'}")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
