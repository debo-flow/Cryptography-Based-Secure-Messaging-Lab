"""
Automated Testing for Milestone 34: Advanced Security Auditing.
Validates Audit Execution, Finding Generation, Compliance Mapping, and Remediation Tracking.
"""
import pytest
import json
from core.database import MetadataDatabase
from core.security_audit_v2 import AdvancedSecurityAuditEngine, SecurityReportGenerator
from core.compliance import ComplianceAnalyzer

@pytest.fixture
def audit_env():
    """Sets up an isolated in-memory DB and the Audit Engine."""
    db = MetadataDatabase(":memory:")
    engine = AdvancedSecurityAuditEngine(db)
    return db, engine

def test_audit_engine_initialization(audit_env):
    db, engine = audit_env
    assert engine.audit_id.startswith("AUDIT-V2-")
    assert len(engine.findings) == 0

def test_manual_finding_insertion(audit_env):
    db, engine = audit_env
    engine._add_finding(
        title="Test Vulnerability",
        category="Dependencies",
        module="requirements.txt",
        severity="High",
        desc="A test vulnerability description.",
        evidence="Test Evidence",
        impact="Test Impact",
        remediation="Test Remediation"
    )
    
    assert len(engine.findings) == 1
    
    # Verify DB insertion
    db_findings = db.get_m34_security_findings()
    assert len(db_findings) == 1
    assert db_findings[0]["title"] == "Test Vulnerability"
    assert db_findings[0]["severity"] == "High"
    assert db_findings[0]["status"] == "Open"

def test_remediation_tracking(audit_env):
    db, engine = audit_env
    engine._add_finding("Vuln1", "E2EE", "core/e2ee_v2.py", "Medium", "Desc", "Evid", "Impact", "Rem")
    
    finding_id = engine.findings[0]["finding_id"]
    
    # Update status to Resolved
    db.update_m34_finding_status(finding_id, "Resolved", "Applied patch to enforce TTL.")
    
    # Verify updated status
    updated_findings = db.get_m34_security_findings(status_filter="Resolved")
    assert len(updated_findings) == 1
    assert updated_findings[0]["finding_id"] == finding_id
    
    # Verify audit trail (Remediation History)
    history = db.get_m34_remediation_history(finding_id)
    assert len(history) == 1
    assert history[0]["status"] == "Resolved"
    assert "patch to enforce TTL" in history[0]["notes"]

def test_compliance_mapping(audit_env):
    db, engine = audit_env
    # M34 Compliance Analyzer should map the current state to NIST/OWASP
    posture = ComplianceAnalyzer.evaluate_compliance_posture(db)
    
    assert "frameworks" in posture
    framework_names = [f["framework"] for f in posture["frameworks"]]
    assert "NIST SP 800-57 (Key Management)" in framework_names
    assert "OWASP ASVS" in framework_names
    
def test_report_generation(audit_env):
    db, engine = audit_env
    engine._add_finding("Vuln1", "E2EE", "core/e2ee_v2.py", "Critical", "Desc", "Evid", "Impact", "Rem")
    
    posture = ComplianceAnalyzer.evaluate_compliance_posture(db)
    
    json_report = SecurityReportGenerator.generate_json(engine.audit_id, engine.findings, posture)
    assert "Vuln1" in json_report
    assert "NIST SP 800-57" in json_report
    
    csv_report = SecurityReportGenerator.generate_csv(engine.findings)
    assert "Vuln1" in csv_report
    assert "Critical" in csv_report
