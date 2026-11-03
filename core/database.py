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
            "CREATE TABLE IF NOT EXISTS hmac_metadata (operation_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL, key_identifier TEXT NOT NULL, timestamp TEXT NOT NULL, operation_type TEXT NOT NULL, status TEXT NOT NULL, format_version TEXT NOT NULL);",
            "CREATE TABLE IF NOT EXISTS ake_metadata (session_id TEXT PRIMARY KEY, initiator TEXT NOT NULL, responder TEXT NOT NULL, status TEXT NOT NULL, timestamp REAL NOT NULL, algorithm_suite TEXT NOT NULL);"
        ]
        with self._get_connection() as conn:
            for query in schema_queries:
                conn.execute(query)
            conn.commit()

    # [... (Other insert/get functions remain identical, abbreviated for compliance on M19 focus. Full output provided for M19 additions)]
    
    def insert_ake_metadata(self, session_id: str, initiator: str, responder: str, status: str, timestamp: float, suite: str) -> None:
        """Stores unclassified public metadata about Authenticated Key Exchanges (M19)."""
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO ake_metadata (session_id, initiator, responder, status, timestamp, algorithm_suite) VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, initiator, responder, status, timestamp, suite)
            )
            conn.commit()
