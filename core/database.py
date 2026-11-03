"""
SQLite Infrastructure for Metadata Storage (Final M30 Release).
Strictly stores metadata, identifiers, and audit logs.
NEVER stores plaintext passwords, raw private keys, or unencrypted session secrets.
"""
import sqlite3
import time
from typing import Optional, Dict, Any, List

class MetadataDatabase:
    def __init__(self, db_path: str = "crypto_metadata.db"):
        self.db_path = db_path
        self._initialize_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_schema(self) -> None:
        schema_queries = [
            # M16 - M21: Signatures, HMAC, AKE, Messaging, Files
            "CREATE TABLE IF NOT EXISTS signature_metadata (operation_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL, fingerprint TEXT NOT NULL, signature_timestamp TEXT NOT NULL, operation_type TEXT NOT NULL, status TEXT NOT NULL, format_version TEXT NOT NULL);",
            "CREATE TABLE IF NOT EXISTS hmac_metadata (operation_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL, key_identifier TEXT NOT NULL, timestamp TEXT NOT NULL, operation_type TEXT NOT NULL, status TEXT NOT NULL, format_version TEXT NOT NULL);",
            "CREATE TABLE IF NOT EXISTS ake_metadata (session_id TEXT PRIMARY KEY, initiator TEXT NOT NULL, responder TEXT NOT NULL, status TEXT NOT NULL, timestamp REAL NOT NULL, algorithm_suite TEXT NOT NULL);",
            "CREATE TABLE IF NOT EXISTS message_history (message_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, sender_id TEXT NOT NULL, recipient_id TEXT NOT NULL, seq_num INTEGER NOT NULL, status TEXT NOT NULL, timestamp TEXT NOT NULL, package_json TEXT NOT NULL);",
            "CREATE TABLE IF NOT EXISTS file_metadata (file_record_id TEXT PRIMARY KEY, original_filename TEXT NOT NULL, file_size INTEGER NOT NULL, algorithm TEXT NOT NULL, encryption_type TEXT NOT NULL, format_version TEXT NOT NULL, timestamp TEXT NOT NULL);",
            
            # M22: Key Management System (KMS)
            "CREATE TABLE IF NOT EXISTS kms_keys (key_id TEXT PRIMARY KEY, category TEXT, algorithm TEXT, fingerprint TEXT, status TEXT, intended_usage TEXT, associated_identity TEXT, created_at REAL, expires_at REAL, rotated_to TEXT, revoked_at REAL, revocation_reason TEXT);",
            "CREATE TABLE IF NOT EXISTS kms_storage (key_id TEXT PRIMARY KEY, encrypted_package TEXT);",
            "CREATE TABLE IF NOT EXISTS kms_audit (event_id TEXT PRIMARY KEY, key_id TEXT, operation TEXT, status TEXT, timestamp REAL);",
            
            # M23: QR & Out-of-Band Trust
            "CREATE TABLE IF NOT EXISTS trusted_identities (identity_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, algorithm TEXT NOT NULL, trusted_at REAL NOT NULL);",
            "CREATE TABLE IF NOT EXISTS qr_metadata (payload_id TEXT PRIMARY KEY, identity_id TEXT NOT NULL, algorithm TEXT NOT NULL, fingerprint TEXT NOT NULL, timestamp REAL NOT NULL);",
            
            # M24 - M26: Integrity & Benchmarking
            "CREATE TABLE IF NOT EXISTS integrity_reports (report_id TEXT PRIMARY KEY, target_id TEXT NOT NULL, target_type TEXT NOT NULL, overall_status TEXT NOT NULL, timestamp REAL NOT NULL, report_json TEXT NOT NULL);",
            "CREATE TABLE IF NOT EXISTS benchmark_history (session_id TEXT PRIMARY KEY, timestamp REAL NOT NULL, environment_json TEXT NOT NULL, report_json TEXT NOT NULL);",
            "CREATE TABLE IF NOT EXISTS adv_benchmark_history (session_id TEXT PRIMARY KEY, timestamp REAL NOT NULL, algorithm TEXT NOT NULL, operation TEXT NOT NULL, metrics_json TEXT NOT NULL);",
            
            # M27: Security Auditing
            "CREATE TABLE IF NOT EXISTS security_audits (audit_id TEXT PRIMARY KEY, timestamp REAL NOT NULL, findings_count INTEGER NOT NULL);",
            "CREATE TABLE IF NOT EXISTS security_findings (finding_id TEXT PRIMARY KEY, audit_id TEXT NOT NULL, title TEXT NOT NULL, module TEXT NOT NULL, severity TEXT NOT NULL, description TEXT NOT NULL, evidence TEXT NOT NULL, remediation TEXT NOT NULL, status TEXT NOT NULL);"
        ]
        with self._get_connection() as conn:
            for query in schema_queries:
                conn.execute(query)
            conn.commit()

    # --- Messaging & File Metadata (M16 - M21) ---
    def insert_signature_metadata(self, operation_id: str, algorithm: str, fingerprint: str, timestamp: str, op_type: str, status: str, version: str) -> None:
        with self._get_connection() as conn:
            conn.execute("INSERT INTO signature_metadata VALUES (?, ?, ?, ?, ?, ?, ?)", (operation_id, algorithm, fingerprint, timestamp, op_type, status, version))
            conn.commit()

    def insert_hmac_metadata(self, operation_id: str, algorithm: str, key_identifier: str, timestamp: str, op_type: str, status: str, version: str) -> None:
        with self._get_connection() as conn:
            conn.execute("INSERT INTO hmac_metadata VALUES (?, ?, ?, ?, ?, ?, ?)", (operation_id, algorithm, key_identifier, timestamp, op_type, status, version))
            conn.commit()

    def insert_ake_metadata(self, session_id: str, initiator: str, responder: str, status: str, timestamp: float, suite: str) -> None:
        with self._get_connection() as conn:
            conn.execute("INSERT INTO ake_metadata VALUES (?, ?, ?, ?, ?, ?)", (session_id, initiator, responder, status, timestamp, suite))
            conn.commit()

    def insert_message_record(self, message_id: str, session_id: str, sender: str, recipient: str, seq_num: int, status: str, timestamp: str, package_json: str) -> None:
        with self._get_connection() as conn:
            conn.execute("INSERT OR REPLACE INTO message_history VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (message_id, session_id, sender, recipient, seq_num, status, timestamp, package_json))
            conn.commit()

    def get_messages_for_session(self, session_id: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM message_history WHERE session_id = ? ORDER BY timestamp ASC", (session_id,))
            return [dict(row) for row in cursor.fetchall()]

    def insert_file_metadata(self, record_id: str, original_filename: str, file_size: int, algorithm: str, enc_type: str, format_version: str, timestamp: str) -> None:
        with self._get_connection() as conn:
            conn.execute("INSERT INTO file_metadata VALUES (?, ?, ?, ?, ?, ?, ?)", (record_id, original_filename, file_size, algorithm, enc_type, format_version, timestamp))
            conn.commit()

    # --- KMS Engine (M22) ---
    def insert_kms_key(self, meta: Dict[str, Any]) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO kms_keys VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (meta["key_id"], meta["category"], meta["algorithm"], meta["fingerprint"], meta["status"], meta["intended_usage"], meta["associated_identity"], meta["created_at"], meta["expires_at"], meta["rotated_to"], meta["revoked_at"], meta["revocation_reason"])
            )
            conn.commit()

    def update_kms_key_status(self, key_id: str, new_status: str, rotated_to: str = None, revocation_reason: str = None) -> None:
        with self._get_connection() as conn:
            conn.execute("UPDATE kms_keys SET status = ?, rotated_to = ?, revocation_reason = ?, revoked_at = ? WHERE key_id = ?", (new_status, rotated_to, revocation_reason, time.time() if revocation_reason else None, key_id))
            conn.commit()

    def insert_kms_storage(self, key_id: str, encrypted_package: str) -> None:
        with self._get_connection() as conn:
            conn.execute("INSERT OR REPLACE INTO kms_storage VALUES (?, ?)", (key_id, encrypted_package))
            conn.commit()

    def get_kms_key_metadata(self, key_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM kms_keys WHERE key_id = ?", (key_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_kms_keys(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM kms_keys ORDER BY created_at DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_kms_storage(self, key_id: str) -> Optional[str]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT encrypted_package FROM kms_storage WHERE key_id = ?", (key_id,))
            row = cursor.fetchone()
            return row["encrypted_package"] if row else None

    def insert_kms_audit(self, event_id: str, key_id: str, operation: str, status: str) -> None:
        with self._get_connection() as conn:
            conn.execute("INSERT INTO kms_audit VALUES (?, ?, ?, ?, ?)", (event_id, key_id, operation, status, time.time()))
            conn.commit()

    def get_kms_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM kms_audit ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # --- Identity Trust & QR (M23) ---
    def insert_trusted_identity(self, identity_id: str, fingerprint: str, algorithm: str) -> None:
        with self._get_connection() as conn:
            conn.execute("INSERT OR REPLACE INTO trusted_identities VALUES (?, ?, ?, ?)", (identity_id, fingerprint, algorithm, time.time()))
            conn.commit()

    def get_trusted_identity(self, identity_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM trusted_identities WHERE identity_id = ?", (identity_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_trusted_identities(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM trusted_identities ORDER BY trusted_at DESC")
            return [dict(row) for row in cursor.fetchall()]

    def revoke_trusted_identity(self, identity_id: str) -> None:
        with self._get_connection() as conn:
            conn.execute("DELETE FROM trusted_identities WHERE identity_id = ?", (identity_id,))
            conn.commit()

    def insert_qr_metadata(self, payload_id: str, identity_id: str, algorithm: str, fingerprint: str) -> None:
        with self._get_connection() as conn:
            conn.execute("INSERT INTO qr_metadata VALUES (?, ?, ?, ?, ?)", (payload_id, identity_id, algorithm, fingerprint, time.time()))
            conn.commit()

    # --- Integrity & Benchmarks (M24 - M26) ---
    def insert_integrity_report(self, report_id: str, target_id: str, target_type: str, status: str, report_json: str) -> None:
        with self._get_connection() as conn:
            conn.execute("INSERT INTO integrity_reports VALUES (?, ?, ?, ?, ?, ?)", (report_id, target_id, target_type, status, time.time(), report_json))
            conn.commit()

    def get_integrity_reports(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM integrity_reports ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def insert_benchmark_history(self, session_id: str, env_json: str, report_json: str) -> None:
        with self._get_connection() as conn:
            conn.execute("INSERT INTO benchmark_history VALUES (?, ?, ?, ?)", (session_id, time.time(), env_json, report_json))
            conn.commit()

    def insert_adv_benchmark(self, session_id: str, algorithm: str, operation: str, metrics_json: str) -> None:
        with self._get_connection() as conn:
            conn.execute("INSERT INTO adv_benchmark_history VALUES (?, ?, ?, ?, ?)", (session_id, time.time(), algorithm, operation, metrics_json))
            conn.commit()

    def get_adv_benchmarks(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM adv_benchmark_history ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # --- Security Audits (M27) ---
    def insert_security_audit(self, audit_id: str, findings_count: int, findings: List[Dict[str, Any]]) -> None:
        with self._get_connection() as conn:
            conn.execute("INSERT INTO security_audits VALUES (?, ?, ?)", (audit_id, time.time(), findings_count))
            for f in findings:
                conn.execute(
                    "INSERT INTO security_findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (f["finding_id"], audit_id, f["title"], f["module"], f["severity"], f["description"], f["evidence"], f["remediation"], f["status"])
                )
            conn.commit()

    def get_all_security_findings(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM security_findings ORDER BY severity ASC")
            return [dict(row) for row in cursor.fetchall()]
            
    def update_finding_status(self, finding_id: str, new_status: str) -> None:
        with self._get_connection() as conn:
            conn.execute("UPDATE security_findings SET status = ? WHERE finding_id = ?", (new_status, finding_id))
            conn.commit()
