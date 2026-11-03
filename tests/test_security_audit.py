"""
Automated Testing for Milestone 27: Security Analysis Dashboard.
Validates the read-only audit engine, severity classifications, and finding generation.
"""
import pytest
from core.database import MetadataDatabase
from core.security_audit import SecurityAuditEngine, FindingSeverity, FindingStatus

@pytest.fixture
def mock_db(tmp_path):
    db_file = tmp_path / "test_audit.db"
    return MetadataDatabase(str(db_file))

def test_audit_engine_initialization(mock_db):
    engine = SecurityAuditEngine(mock_db)
    assert engine.audit_id is not None
    assert len(engine.findings) == 0

def test_kms_audit_expired_key(mock_db):
    # Inject an expired key
    import time
    past_time = time.time() - 10000
    mock_db.insert_kms_key({
        "key_id": "test-expired-key",
        "category": "SYMMETRIC",
        "algorithm": "AES-256",
        "fingerprint": None,
        "status": "ACTIVE",
        "intended_usage": "Test",
        "associated_identity": "System",
        "created_at": past_time - 1000,
        "expires_at": past_time,
        "rotated_to": None,
        "revoked_at": None,
        "revocation_reason": None
    })
    
    engine = SecurityAuditEngine(mock_db)
    engine.audit_key_management()
    
    assert len(engine.findings) == 1
    finding = engine.findings[0]
    assert finding.severity == FindingSeverity.HIGH.value
    assert finding.title == "Expired Key Marked as ACTIVE"
    assert "test-expired-key" in finding.description

def test_database_schema_audit(mock_db):
    engine = SecurityAuditEngine(mock_db)
    engine.audit_database_security()
    
    # Standard DB schema in our project should have ZERO critical plaintext findings
    # (Since we strictly avoid storing 'plaintext' or 'password' as column names)
    critical_db_findings = [f for f in engine.findings if f.severity == FindingSeverity.CRITICAL.value]
    assert len(critical_db_findings) == 0

def test_dependency_audit(mock_db):
    engine = SecurityAuditEngine(mock_db)
    engine.audit_dependencies()
    # It shouldn't crash. Result depends on the environment running the test.
    assert isinstance(engine.findings, list)
