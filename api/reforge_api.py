"""
█ TRISHULA REFORGE-AS-A-SERVICE (RaaS)
Semantic Self-Healing API — SQA_v5 [ASCENDED]
[MARKET OPPORTUNITY: SELF-HEALING PIPELINES FOR EXTERNAL FLEETS]
"""

import os
import json
from flask import Flask, request, jsonify
from Enforcer.healer_daemon import HealerDaemon
from Security_Janitor.modules.audit_signer import AuditSigner

app = Flask(__name__)
healer = HealerDaemon()
signer = AuditSigner("RAAS-PROVIDER-01")

@app.route('/api/v1/reforge', methods=['POST'])
def reforge_endpoint():
    """
    Exposes the Healer-Daemon's reforge logic as a secure API.
    Input: { "veto_finding": { "reason": "...", "payload": "..." } }
    Output: PQC-signed correction.
    """
    data = request.get_json()
    if not data or 'veto_finding' not in data:
        return jsonify({"status": "ERROR", "message": "Missing veto_finding"}), 400
    
    # 1. Perform the Reforge
    reforge_result = healer.reforge_pulse(data['veto_finding'])
    
    # 2. Sign the Result (ASA Integration)
    signed_result = signer.sign_audit_report(reforge_result)
    
    return jsonify(signed_result)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "SOVEREIGN", "engine": "Healer-v2", "pqc": "ML-KEM-768"})

if __name__ == "__main__":
    # RaaS Deployment: Initializing on port 5050
    print("=== TRISHULA RaaS: STARTING SOVEREIGN API ===")
    app.run(host='0.0.0.0', port=5050)
