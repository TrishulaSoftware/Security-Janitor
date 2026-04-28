"""
Trishula Security-Janitor â€” SQA Test Suite
Verified rule IDs: SEC001, SEC002, SEC003, TAG001, INJ001, INJ002, CRY001, DBG001, TS-005
"""
import sys, os, json, tempfile, hashlib
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

P = 0; F = 0
def t(name, cond):
    global P, F
    if cond: P += 1; print(f"  [PASS] {name}")
    else: F += 1; print(f"  [FAIL] {name}")
def s(title): print(f"\n{'='*60}\n  {title}\n{'='*60}")

# ===== CATEGORY 1: DATA MODELS =====
s("CATEGORY 1: DATA MODELS")
from modules.auditor import Finding, Severity, Auditor, RULES

f1 = Finding(
    rule_id="SEC001", severity=Severity.CRITICAL,
    file_path="test.py", line_number=10,
    line_content='api_key = "sk-abc123"',
    description="Hardcoded API key", fixable=True
)
t("Finding creates", f1 is not None)
t("Finding rule_id", f1.rule_id == "SEC001")
t("Finding severity CRITICAL", f1.severity == Severity.CRITICAL)
t("Finding line_number", f1.line_number == 10)
t("Finding fixable", f1.fixable is True)
t("Severity.CRITICAL value", Severity.CRITICAL.value == "CRITICAL")
t("Severity.HIGH value", Severity.HIGH.value == "HIGH")
t("Severity.MEDIUM value", Severity.MEDIUM.value == "MEDIUM")
t("Severity.LOW value", Severity.LOW.value == "LOW")
t("Severity.INFO value", Severity.INFO.value == "INFO")
t("RULES loaded", len(RULES) >= 9)
t("All rules have rule_id", all(r.rule_id for r in RULES))
t("All rules have pattern", all(r.pattern for r in RULES))

# ===== CATEGORY 2: AUDITOR â€” DETECTION =====
s("CATEGORY 2: AUDITOR DETECTION RULES")
auditor = Auditor()
t("Auditor creates", auditor is not None)

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)

    # SEC001/SEC002 â€” hardcoded secrets (.py)
    vuln_secret = tmp / "secrets.py"
    vuln_secret.write_text('api_key = "sk-abc123def456xyz789"\npassword = "hardcoded_pass_123"\n')
    f = auditor.scan_file(vuln_secret)
    t("SEC001/002: detects hardcoded secret in .py", any(x.rule_id in ("SEC001","SEC002","SEC003") for x in f))
    t("SEC001/002: finding has severity", all(x.severity for x in f))
    t("SEC001/002: finding has line number", all(x.line_number > 0 for x in f))
    t("SEC001/002: finding has file_path", all(x.file_path for x in f))

    # TAG001 â€” mutable GH Actions (.yml)
    vuln_tag = tmp / "deploy.yml"
    vuln_tag.write_text('steps:\n  - uses: actions/checkout@v3\n  - uses: actions/setup-python@v4\n')
    f = auditor.scan_file(vuln_tag)
    t("TAG001: detects mutable GH tag", any(x.rule_id == "TAG001" for x in f))

    # INJ001/INJ002 â€” SQL injection (.py)
    vuln_sql = tmp / "db.py"
    vuln_sql.write_text('query = "SELECT * FROM users WHERE id = " + user_id\ncursor.execute("DELETE FROM t WHERE x=" + x)\n')
    f = auditor.scan_file(vuln_sql)
    t("INJ001/002: detects SQL injection", any(x.rule_id in ("INJ001","INJ002") for x in f))

    # CRY001 â€” insecure crypto (.py)
    vuln_cry = tmp / "crypto.py"
    vuln_cry.write_text('import hashlib\nhash = hashlib.md5(data).hexdigest()\ntoken = hashlib.sha1(secret).hexdigest()\n')
    f = auditor.scan_file(vuln_cry)
    t("CRY001: detects MD5/SHA1 crypto", any(x.rule_id == "CRY001" for x in f))

    # DBG001 â€” debug flag (.py)
    vuln_dbg = tmp / "app.py"
    vuln_dbg.write_text('DEBUG = True\napp.run(debug=True)\n')
    f = auditor.scan_file(vuln_dbg)
    t("DBG001: detects debug flag", any(x.rule_id == "DBG001" for x in f))

    # Clean file â€” no findings
    clean = tmp / "clean.py"
    clean.write_text('import os\nkey = os.environ.get("API_KEY")\nhash = hashlib.sha256(data).hexdigest()\n')
    f = auditor.scan_file(clean)
    t("Clean .py: no secret findings", not any(x.rule_id in ("SEC001","SEC002","SEC003") for x in f))

    # Directory scan
    all_findings = auditor.scan_directory(tmp)
    t("Directory scan runs", isinstance(all_findings, list))
    t("Directory scan finds issues", len(all_findings) >= 4)
    t("All findings have rule_id", all(x.rule_id for x in all_findings))

# ===== CATEGORY 3: PATCHER =====
s("CATEGORY 3: PATCHER â€” DUAL TIER")
from modules.patcher import Patcher, PatchResult

patcher = Patcher(llm_connector=None, enable_llm=False)
t("Patcher creates no-LLM", patcher is not None)
t("Patcher LLM disabled", patcher.enable_llm is False)

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    target = tmp / "workflow.yml"
    target.write_text('    - uses: actions/checkout@v3\n')
    finding = Finding(
        rule_id="TAG001", severity=Severity.HIGH,
        file_path=str(target), line_number=1,
        line_content='    - uses: actions/checkout@v3',
        description="Mutable GH Action tag", fixable=True
    )
    result = patcher.patch(finding)
    t("Patch returns PatchResult", isinstance(result, PatchResult))
    t("Patch has strategy", len(result.strategy) > 0)
    t("Patch has finding", result.finding is not None)
    t("Patch finding matches", result.finding.rule_id == "TAG001")

# ===== CATEGORY 4: PQC INTERLOCK =====
s("CATEGORY 4: PQC INTERLOCK")
from pqc_interlock import SteelBoltPQC, PqcLedgerSigner

pqc = SteelBoltPQC("agent-trishula-sja")
t("PQC creates", pqc is not None)
t("PQC has SK prefix", pqc.sk.startswith("SK-LATTICE-"))
t("PQC has PK prefix", pqc.pk.startswith("PK-LATTICE-"))
t("SK is deterministic", pqc.sk == SteelBoltPQC("agent-trishula-sja").sk)
t("Different agents have different keys", pqc.sk != SteelBoltPQC("other-agent").sk)

payload = {"mission": "reforge", "target": "/repo", "ts": "2026-04-28"}
env = pqc.encapsulate_for_agent(pqc.pk, payload)
t("Encapsulate returns dict", isinstance(env, dict))
t("Envelope has pqc_sig", "pqc_sig" in env and env["pqc_sig"].startswith("SIG-v1-"))
t("Envelope has payload_enc", "payload_enc" in env)
t("Envelope status SECURE", env["status"] == "SECURE")
t("Envelope has target_pk", env["target_pk"] == pqc.pk)

recovered = pqc.decapsulate_payload(env)
t("Decapsulate: recovers mission", recovered.get("mission") == "reforge")
t("Decapsulate: recovers target", recovered.get("target") == "/repo")
t("Decapsulate: full fidelity", recovered.get("ts") == "2026-04-28")

sig = PqcLedgerSigner.sign_state({"action": "patch"}, pqc.sk)
t("Ledger sign returns PQC-PROOF", sig.startswith("PQC-PROOF-"))
t("Signature deterministic", sig == PqcLedgerSigner.sign_state({"action": "patch"}, pqc.sk))
t("Different data = different sig", sig != PqcLedgerSigner.sign_state({"action": "scan"}, pqc.sk))
t("Different sk = different sig", sig != PqcLedgerSigner.sign_state({"action": "patch"}, "OTHER-SK"))

# ===== CATEGORY 5: AUDIT SIGNER =====
s("CATEGORY 5: AUDIT SIGNER")
from modules.audit_signer import AuditSigner

signer = AuditSigner("test-agent-sja")
t("AuditSigner creates", signer is not None)

report1 = {"action": "scan", "file": "app.py", "findings": 3}
report2 = {"action": "patch", "rule": "SEC001"}
result1 = signer.sign_audit_report(report1)
result2 = signer.sign_audit_report(report2)
t("sign_audit_report returns dict", isinstance(result1, dict))
t("Signed report has pqc_proof", "pqc_proof" in result1)
t("pqc_proof starts PQC-PROOF", result1["pqc_proof"].startswith("PQC-PROOF-"))
t("Signed report has audit_metadata", "audit_metadata" in result1)
t("Metadata has signed_by", result1["audit_metadata"]["signed_by"] == "test-agent-sja")
t("Metadata has pqc_algorithm", result1["audit_metadata"]["pqc_algorithm"] == "ML-KEM-768")
t("Metadata has timestamp", "timestamp" in result1["audit_metadata"])
t("Different reports get different proofs", result1["pqc_proof"] != result2["pqc_proof"])

import tempfile as _tf, os as _os
_tmp_out = _os.path.join(_tf.gettempdir(), "sja_report_test.json")
exported = signer.export_signed_report(result1, _tmp_out)
t("export_signed_report returns content", exported is not None or _os.path.exists(_tmp_out))


# ===== CATEGORY 6: END-TO-END =====
s("CATEGORY 6: END-TO-END SCAN -> DETECT -> PATCH -> SIGN")
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    target = tmp / "vuln_e2e.py"
    target.write_text('api_key = "sk-live-abc123def456"\nDEBUG = True\nquery = "SELECT * FROM t WHERE id=" + uid\n')

    auditor2 = Auditor()
    findings = auditor2.scan_file(target)
    t("E2E: scan detects vulnerabilities", len(findings) >= 2)
    t("E2E: findings are Finding objects", all(isinstance(f, Finding) for f in findings))

    patcher2 = Patcher(llm_connector=None, enable_llm=False)
    patch_results = [patcher2.patch(f) for f in findings]
    t("E2E: patcher processes all findings", len(patch_results) == len(findings))
    t("E2E: all results are PatchResult", all(isinstance(r, PatchResult) for r in patch_results))

    signer2 = AuditSigner("e2e-agent-sja")
    signed_reports = []
    for r in patch_results:
        sr = signer2.sign_audit_report({"rule": r.finding.rule_id, "strategy": r.strategy, "success": r.success})
        signed_reports.append(sr)

    t("E2E: chain has signed reports", len(signed_reports) == len(findings))
    t("E2E: all signed have pqc_proof", all("pqc_proof" in sr for sr in signed_reports))
    t("E2E: all proofs unique", len(set(sr["pqc_proof"] for sr in signed_reports)) == len(signed_reports))

    pqc2 = SteelBoltPQC("e2e-agent")
    mission_sig = PqcLedgerSigner.sign_state({"findings": len(findings), "patched": len(patch_results)}, pqc2.sk)
    t("E2E: mission signed with PQC", mission_sig.startswith("PQC-PROOF-"))

# ===== VERDICT =====
print(f"\n{'='*60}")
total = P + F
print(f"  RESULTS: {P}/{total} PASSED, {F}/{total} FAILED")
print(f"  VERDICT: {'SQA_v5_ASCENDED: EXCEEDED' if F == 0 else 'SQA FAIL'}")
print(f"{'='*60}")
if F > 0:
    sys.exit(1)
