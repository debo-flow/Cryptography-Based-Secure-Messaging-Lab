"""
SQLite Infrastructure for Metadata Storage.
Strictly stores metadata and identifiers, NEVER plaintext secrets.
"""

import sqlite3
from typing import Optional
from .metadata import KeyMetadata, KeyStatus

class MetadataDatabase:
    """Lightweight SQLite wrapper for cryptographic metadata tracking."""
    
    def __init__(self, db_path: str = "crypto_metadata.db"):
        self.db_path = db_path
        self._initialize_schema()

    def _get_connection(self) -> sqlite3.Connection:
        # SQLite connection per thread, avoiding locking errors in Streamlit
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_schema(self) -> None:
        """Sets up required tables securely via parameterized setups."""
        schema_queries = [
            """
            CREATE TABLE IF NOT EXISTS key_metadata (
                key_id TEXT PRIMARY KEY,
                algorithm TEXT NOT NULL,
                purpose TEXT NOT NULL,
                status TEXT NOT NULL,
                version INTEGER NOT NULL,
                created_at REAL NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS nonce_metadata (
                nonce_id TEXT PRIMARY KEY,
                algorithm TEXT NOT NULL,
                associated_key_id TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """
        ]
        
        with self._get_connection() as conn:
            for query in schema_queries:
                conn.execute(query)
            conn.commit()

    def insert_key_metadata(self, metadata: KeyMetadata) -> None:
        """Safely inserts metadata using parameterized query."""
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO key_metadata (key_id, algorithm, purpose, status, version, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (metadata.key_id, metadata.algorithm, metadata.purpose, metadata.status.value, metadata.version, metadata.created_at)
            )
            conn.commit()

    def get_key_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        """Retrieves non-secret key metadata by ID."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM key_metadata WHERE key_id = ?", (key_id,))
            row = cursor.fetchone()
            
            if row:
                return KeyMetadata(
                    key_id=row["key_id"],
                    algorithm=row["algorithm"],
                    purpose=row["purpose"],
                    status=KeyStatus(row["status"]),
                    version=row["version"],
                    created_at=row["created_at"]
                )
        return None
