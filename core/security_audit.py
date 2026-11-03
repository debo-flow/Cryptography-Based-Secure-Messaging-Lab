"""
Advanced Cryptographic Security Analysis Engine (M27).
Audits cryptographic configurations, Key Management (KMS) lifecycles, SQLite schema safety, 
and dependencies to generate sanitized security findings and remediation reports.
"""

import time
import uuid
import json
import io
import csv
import importlib.metadata
from enum import Enum
from typing import Dict, Any, List

from .database import MetadataDatabase
from .registry import ALGORITHM_REGISTRY

class FindingSeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

class FindingStatus(Enum):
    OPEN = "Open"
    RESOLVED = "Resolved"
    ACKNOWLEDGED = "Acknowledged"
    RISK_ACCEPTED = "Accepted Risk"

class SecurityFinding:
    """Represents a structured security finding from the audit engine."""
    def __init__(self, title: str, module: str, severity: FindingSeverity, description: str, evidence: str, remediation: str):
        self.finding_id = str(uuid.uuid4())
        self.timestamp = time.time()
        self.title = title
        self.module = module
        self.severity = severity.value
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.status = FindingStatus.OPEN.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "timestamp": self.timestamp,
            "title": self.title,
            "module": self.module,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "status": self.status
        }

class SecurityAuditEngine:
    """Executes read-only audits across project modules to identify security weaknesses."""
    
    def __init__(self, db: MetadataDatabase):
        self.db = db
        self.findings: List[SecurityFinding] = []
        self.audit_id = str(uuid.uuid4())
        self.timestamp = time.time()

    def run_full_audit(self) -> List[SecurityFinding]:
        self.findings.clear()
        self.audit_cryptographic_configuration()
        self.audit_key_management()
        self.audit_database_security()
        self.audit_dependencies()
        return self.findings

    def audit_cryptographic_configuration(self):
        """Audits the ALGORITHM_REGISTRY for deprecated or weak configurations."""
        weak_algos = ["MD5", "SHA1", "DES", "RC4"] # Example deprecated algorithms
        
        for algo_name, meta in ALGORITHM_REGISTRY.items():
            if any(weak in algo_name for weak in weak_algos):
                self.findings.append(SecurityFinding(
                    title=f"Deprecated Algorithm Detected: {algo_name}",
                    module="Cryptographic Core Engine",
                    severity=FindingSeverity.CRITICAL,
                    description=f"The registry contains {algo_name}, which is cryptographically broken.",
                    evidence=f"Registry Entry: {meta.category}",
                    remediation=f"Remove {algo_name} and replace with a modern primitive (e.g., AES-GCM or SHA-256)."
                ))

    def audit_key_management(self):
        """Audits the KMS tables for expired keys, compromised keys still active, etc."""
        keys = self.db.get_all_kms_keys()
        current_time = time.time()
        
        for key in keys:
            # Check expiration
            if key.get("expires_at") and key["expires_at"] < current_time and key["status"] == "ACTIVE":
                self.findings.append(SecurityFinding(
                    title="Expired Key Marked as ACTIVE",
                    module="Key Management Engine",
                    severity=FindingSeverity.HIGH,
                    description=f"Key {key['key_id']} has passed its expiration date but remains ACTIVE.",
                    evidence=f"Expires: {key['expires_at']}, Status: {key['status']}",
                    remediation="Rotate the key immediately and mark the old key as EXPIRED."
                ))
            
            # Check compromised keys
            if key["status"] == "COMPROMISED":
                self.findings.append(SecurityFinding(
                    title="Compromised Key Retained in Database",
                    module="Key Management Engine",
                    severity=FindingSeverity.INFORMATIONAL,
                    description=f"Key {key['key_id']} is marked COMPROMISED.",
                    evidence=f"Revocation Reason: {key.get('revocation_reason')}",
                    remediation="Ensure this key is never used for new encryption operations. Retain only for forensic decryption if strictly necessary."
                ))

    def audit_database_security(self):
        """Inspects the SQLite schema to ensure plaintext fields aren't accidentally declared."""
        schema_query = "SELECT sql FROM sqlite_master WHERE type='table';"
        with self.db._get_connection() as conn:
            cursor = conn.execute(schema_query)
            schemas = cursor.fetchall()
            
        unsafe_keywords = ["plaintext", "password", "raw_secret", "private_key"]
        
        for row in schemas:
            sql = row["sql"].lower()
            for kw in unsafe_keywords:
                # We specifically look for column names that match unsafe patterns
                if kw in sql and not "encrypted" in sql and not "metadata" in sql:
                    self.findings.append(SecurityFinding(
                        title="Potential Secret Material in SQLite Schema",
                        module="Database Infrastructure",
                        severity=FindingSeverity.CRITICAL,
                        description=f"The database schema contains a column mimicking plaintext storage: '{kw}'.",
                        evidence=f"Schema extract: {sql[:50]}...",
                        remediation="Drop the column. Cryptographic secrets must only be stored encrypted at rest (e.g., KMS Storage Blob)."
                    ))
                    
    def audit_dependencies(self):
        """Analyzes active python dependency versions for known structural weaknesses."""
        try:
            crypto_version = importlib.metadata.version('cryptography')
            major_version = int(crypto_version.split('.')[0])
            
            if major_version < 41:
                self.findings.append(SecurityFinding(
                    title="Outdated 'cryptography' Library",
                    module="Dependency Auditor",
                    severity=FindingSeverity.MEDIUM,
                    description=f"Installed cryptography version {crypto_version} is aging. Newer versions provide better memory-safe Rust bindings.",
                    evidence=f"Active version: {crypto_version}",
                    remediation="Run `pip install --upgrade cryptography`."
                ))
        except importlib.metadata.PackageNotFoundError:
            pass # Not found in this execution context (e.g., embedded environments)
