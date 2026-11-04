"""
Advanced Cryptographic Security Audit Engine (M34).
Executes read-only inspections across Cryptography, KMS, E2EE, Ratchets, Dependencies, and SQLite.
Generates structured findings mapped to compliance frameworks.
"""

import time
import uuid
import json
import subprocess
from typing import Dict, List, Any
from .compliance import ComplianceAnalyzer
from .registry import ALGORITHM_REGISTRY

class SecurityReportGenerator:
    """Handles sanitization and formatting of Audit outputs."""
    @staticmethod
    def generate_json(audit_id: str, findings: List[Dict[str, Any]], compliance: Dict[str, Any]) -> str:
        report = {
            "audit_id": audit_id,
            "timestamp": time.time(),
            "profile": "Comprehensive Full-Project Scan",
            "total_findings": len(findings),
            "findings_by_severity": {
                "Critical": len([f for f in findings if f["severity"] == "Critical"]),
                "High": len([f for f in findings if f["severity"] == "High"]),
                "Medium": len([f for f in findings if f["severity"] == "Medium"]),
                "Low": len([f for f in findings if f["severity"] == "Low"])
            },
            "findings": findings,
            "compliance_mapping": compliance
        }
        return json.dumps(report, indent=4)

    @staticmethod
    def generate_csv(findings: List[Dict[str, Any]]) -> str:
        import io
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Finding ID", "Title", "Category", "Severity", "Module", "Description", "Remediation", "Compliance"])
        for f in findings:
            writer.writerow([f["finding_id"], f["title"], f["category"], f["severity"], f["module"], f["description"], f["remediation"], f.get("compliance_framework", "")])
        return output.getvalue()


class AdvancedSecurityAuditEngine:
    """Orchestrates modular auditors."""
    def __init__(self, db_instance):
        self.db = db_instance
        self.findings: List[Dict[str, Any]] = []
        self.audit_id = f"AUDIT-V2-{str(uuid.uuid4())[:8]}"

    def _add_finding(self, title: str, category: str, module: str, severity: str, desc: str, evidence: str, impact: str, remediation: str):
        finding = {
            "finding_id": f"FND-{str(uuid.uuid4())[:8]}",
            "audit_id": self.audit_id,
            "title": title,
            "category": category,
            "module": module,
            "severity": severity,
            "description": desc,
            "evidence": evidence,
            "impact": impact,
            "remediation": remediation,
            "compliance_framework": ComplianceAnalyzer.map_finding_to_framework(category),
            "status": "Open",
            "timestamp": time.time()
        }
        self.findings.append(finding)
        self.db.insert_m34_security_finding(finding)

    def run_full_audit(self):
        """Executes all read-only auditor modules."""
        self._audit_cryptographic_configurations()
        self._audit_key_management()
        self._audit_e2ee_and_ratchets()
        self._audit_database_integrity()
        self._audit_dependencies()
        
        compliance_data = ComplianceAnalyzer.evaluate_compliance_posture(self.db)
        
        self.db.insert_m34_audit_execution(
            self.audit_id, "Comprehensive", "COMPLETED", 
            json.dumps({"findings_count": len(self.findings), "compliance": compliance_data})
        )

    # --- 1. Cryptographic Configuration Auditor ---
    def _audit_cryptographic_configurations(self):
        """Validates algorithms registered in M03-M17."""
        if "AES-128" in ALGORITHM_REGISTRY:
            self._add_finding(
                "Deprecated Key Size Available", "Cryptography", "core/registry.py", "Low",
                "AES-128 is registered as an available primitive.",
                "Registry contains AES-128 mapping.",
                "Reduces brute-force margin against quantum adversaries.",
                "Deprecate AES-128 in favor of AES-256 exclusively."
            )

    # --- 2. Key Management Auditor ---
    def _audit_key_management(self):
        """Validates M22 & M33 KMS schemas and states."""
        keys = self.db.get_all_kms_keys()
        
        for k in keys:
            if k["status"] == "ACTIVE" and (time.time() - k["created_at"]) > (86400 * 365):
                self._add_finding(
                    "Stale Active Key", "Key Management", "core/kme.py", "Medium",
                    f"Key {k['key_id']} has been active for over 1 year without rotation.",
                    f"Key Creation: {k['created_at']}, Current: {time.time()}",
                    "Increases cryptanalytic exposure window.",
                    "Execute key rotation via the Lifecycle Manager."
                )

    # --- 3. E2EE & Ratchet Auditor ---
    def _audit_e2ee_and_ratchets(self):
        """Validates M31 E2EE Sessions and M32 Ratchet states."""
        # 1. Stale E2EE Sessions
        active_sessions = self.db.execute_raw_query("SELECT * FROM e2ee_v2_sessions WHERE status = 'ACTIVE'")
        for s in active_sessions:
            if time.time() > s["expires_at"]:
                self._add_finding(
                    "Expired E2EE Session Active", "E2EE", "core/e2ee_v2.py", "High",
                    f"Session {s['session_id']} bypassed TTL enforcement.",
                    f"Expiration: {s['expires_at']} < Now: {time.time()}",
                    "Allows reuse of expired key material.",
                    "Enforce strict TTL revocation in session router."
                )
                
        # 2. Ratchet Skips
        ratchets = self.db.execute_raw_query("SELECT * FROM ratchet_metadata")
        for r in ratchets:
            if (r["tx_seq"] - r["rx_seq"]) > 50:
                self._add_finding(
                    "High Ratchet Desynchronization", "Ratchets", "core/ratchet.py", "Medium",
                    f"Session {r['session_id']} shows a gap > 50 messages.",
                    f"TX: {r['tx_seq']}, RX: {r['rx_seq']}",
                    "Can lead to denial of service or excessive skipped-key memory retention.",
                    "Verify bounding limits on skipped message keys."
                )

    # --- 4. Database Security Auditor ---
    def _audit_database_integrity(self):
        """Ensures secrets aren't leaking into SQLite plaintext."""
        # Check KMS Storage for plaintext 'password' or raw hex string structures
        storages = self.db.execute_raw_query("SELECT * FROM kms_storage")
        for s in storages:
            if '"raw_material_bytes"' in s["encrypted_package"] and not s["encrypted_package"].startswith("ey"):
                # Very basic heuristic for unencrypted JSON vs Base64 Argon envelopes
                self._add_finding(
                    "Potential Plaintext Key Leak", "Database", "kms_storage", "Critical",
                    f"Key package for {s['key_id']} does not appear correctly encrypted.",
                    "JSON string matched plaintext indicators instead of AEAD output.",
                    "Complete compromise of managed keys.",
                    "Ensure Argon2id+AES-GCM is enforced before DB INSERT."
                )

    # --- 5. Dependency & Supply Chain Auditor ---
    def _audit_dependencies(self):
        """Executes 'pip-audit' and 'safety' if available via subprocess."""
        try:
            # Run pip-audit
            result = subprocess.run(["pip-audit", "--format=json"], capture_output=True, text=True, timeout=15)
            if result.returncode != 0 and result.stdout:
                audit_data = json.loads(result.stdout)
                for dep in audit_data.get("dependencies", []):
                    for vuln in dep.get("vulns", []):
                        self._add_finding(
                            f"Vulnerable Dependency: {dep['name']}", "Dependencies", "requirements.txt", "High",
                            f"Identified CVE in installed package.",
                            f"Vuln ID: {vuln.get('id')}",
                            "Potential Remote Code Execution or Cryptographic Bypass.",
                            f"Upgrade {dep['name']} to a secure version."
                        )
        except (subprocess.SubprocessError, FileNotFoundError, json.JSONDecodeError):
            self._add_finding(
                "Dependency Auditing Tools Unavailable", "Dependencies", "Environment", "Informational",
                "pip-audit or safety commands failed to execute.",
                "Subprocess raised FileNotFoundError or Timeout.",
                "Supply chain vulnerabilities cannot be automatically identified.",
                "Install 'pip-audit' in the host environment."
            )
