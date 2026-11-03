"""
SQLite Infrastructure for Metadata Storage.
Strictly stores metadata and identifiers, NEVER plaintext secrets.
"""
import sqlite3
from typing import Optional, Dict, Any
from .metadata import KeyMetadata, KeyStatus

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
            "CREATE TABLE IF NOT EXISTS key_metadata (key_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL, purpose TEXT NOT NULL, status TEXT NOT NULL, version INTEGER NOT NULL, created_at REAL NOT NULL);",
            "CREATE TABLE IF NOT EXISTS nonce_metadata (nonce_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL, associated_key_id TEXT NOT NULL, created_at REAL NOT NULL);",
            "CREATE TABLE IF NOT EXISTS signature_metadata (operation_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL, fingerprint TEXT NOT NULL, signature_timestamp TEXT NOT NULL, operation_type TEXT NOT NULL, status TEXT NOT NULL, format_version TEXT NOT NULL);",
            "CREATE TABLE IF NOT EXISTS hmac_metadata (operation_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL, key_identifier TEXT NOT NULL, timestamp TEXT NOT NULL, operation_type TEXT NOT NULL, status TEXT NOT NULL, format_version TEXT NOT NULL);"
        ]
        with self._get_connection() as conn:
            for query in schema_queries:
                conn.execute(query)
            conn.commit()

    def insert_key_metadata(self, metadata: KeyMetadata) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO key_metadata (key_id, algorithm, purpose, status, version, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (metadata.key_id, metadata.algorithm, metadata.purpose, metadata.status.value, metadata.version, metadata.created_at)
            )
            conn.commit()

    def get_key_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM key_metadata WHERE key_id = ?", (key_id,))
            row = cursor.fetchone()
            if row:
                return KeyMetadata(key_id=row["key_id"], algorithm=row["algorithm"], purpose=row["purpose"], status=KeyStatus(row["status"]), version=row["version"], created_at=row["created_at"])
        return None

    def insert_signature_metadata(self, operation_id: str, algorithm: str, fingerprint: str, timestamp: str, op_type: str, status: str, version: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO signature_metadata (operation_id, algorithm, fingerprint, signature_timestamp, operation_type, status, format_version) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (operation_id, algorithm, fingerprint, timestamp, op_type, status, version)
            )
            conn.commit()

    def insert_hmac_metadata(self, operation_id: str, algorithm: str, key_identifier: str, timestamp: str, op_type: str, status: str, version: str) -> None:
        """Stores unclassified public metadata about HMAC operations for auditing (M17)."""
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO hmac_metadata (operation_id, algorithm, key_identifier, timestamp, operation_type, status, format_version) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (operation_id, algorithm, key_identifier, timestamp, op_type, status, version)
            )
            conn.commit()
