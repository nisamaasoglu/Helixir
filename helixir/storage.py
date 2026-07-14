"""
Audit log — a SQLite record of encryption operations.

What is stored:
  * source name, source SHA-256 (integrity reference for the original input)
  * algorithm / KDF identifiers
  * salt and nonce (NOT secret; needed to decrypt)
  * the ciphertext container (safe: it is AES-256-GCM authenticated-encrypted)
  * DNA length and GC-content (representation metadata)

What is NEVER stored:
  * the passphrase
  * the derived key
  * the plaintext

This is the deliberate fix over the original prototype, which persisted the
encryption key as plaintext.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    source_name   TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    algorithm     TEXT NOT NULL,
    kdf           TEXT NOT NULL,
    salt_hex      TEXT NOT NULL,
    nonce_hex     TEXT NOT NULL,
    dna_length    INTEGER NOT NULL,
    gc_content    REAL NOT NULL,
    container     BLOB NOT NULL
);
"""


@dataclass(frozen=True)
class LogEntry:
    id: int
    created_at: str
    source_name: str
    source_sha256: str
    algorithm: str
    kdf: str
    dna_length: int
    gc_content: float


class AuditLog:
    def __init__(self, db_path: str = "encryption_log.db"):
        self.db_path = db_path
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def record(
        self,
        *,
        source_name: str,
        source_bytes: bytes,
        container: bytes,
        salt_hex: str,
        nonce_hex: str,
        dna_length: int,
        gc_content: float,
        algorithm: str = "AES-256-GCM",
        kdf: str = "scrypt",
    ) -> int:
        """Insert one record and return its id."""
        source_sha256 = hashlib.sha256(source_bytes).hexdigest()
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO audit_log (
                    created_at, source_name, source_sha256, algorithm, kdf,
                    salt_hex, nonce_hex, dna_length, gc_content, container
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at, source_name, source_sha256, algorithm, kdf,
                    salt_hex, nonce_hex, dna_length, gc_content,
                    sqlite3.Binary(container),
                ),
            )
            return int(cur.lastrowid)

    def list_entries(self) -> list[LogEntry]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, source_name, source_sha256, algorithm,
                       kdf, dna_length, gc_content
                FROM audit_log ORDER BY created_at DESC, id DESC
                """
            ).fetchall()
        return [LogEntry(*row) for row in rows]

    def get_container(self, entry_id: int) -> bytes | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT container FROM audit_log WHERE id = ?", (entry_id,)
            ).fetchone()
        return bytes(row[0]) if row else None

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM audit_log")
            conn.execute("DELETE FROM sqlite_sequence WHERE name = 'audit_log'")
