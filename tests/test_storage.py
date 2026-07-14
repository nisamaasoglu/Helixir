import os

from helixir import crypto, dna_codec
from helixir.storage import AuditLog


def _make_log(tmp_path):
    return AuditLog(db_path=str(tmp_path / "test_log.db"))


def test_record_and_list(tmp_path):
    log = _make_log(tmp_path)
    source = b"hello world"
    dna, result = crypto.encrypt_to_dna(source, "pw")
    entry_id = log.record(
        source_name="hello.txt",
        source_bytes=source,
        container=result.container,
        salt_hex=result.salt_hex,
        nonce_hex=result.nonce_hex,
        dna_length=len(dna),
        gc_content=dna_codec.gc_content(dna),
    )
    entries = log.list_entries()
    assert len(entries) == 1
    assert entries[0].id == entry_id
    assert entries[0].source_name == "hello.txt"
    assert entries[0].algorithm == "AES-256-GCM"


def test_container_roundtrips_from_db(tmp_path):
    log = _make_log(tmp_path)
    source = os.urandom(500)
    _, result = crypto.encrypt_to_dna(source, "pw")
    entry_id = log.record(
        source_name="blob.bin",
        source_bytes=source,
        container=result.container,
        salt_hex=result.salt_hex,
        nonce_hex=result.nonce_hex,
        dna_length=0,
        gc_content=0.0,
    )
    stored = log.get_container(entry_id)
    assert crypto.decrypt(stored, "pw") == source


def test_no_secret_columns_exist(tmp_path):
    # The schema must not contain a key/passphrase/plaintext column.
    log = _make_log(tmp_path)
    import sqlite3

    with sqlite3.connect(log.db_path) as conn:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(audit_log)")]
    lowered = {c.lower() for c in cols}
    assert not (lowered & {"key", "key_used", "passphrase", "password", "plaintext"})


def test_clear(tmp_path):
    log = _make_log(tmp_path)
    _, result = crypto.encrypt_to_dna(b"x", "pw")
    log.record(
        source_name="x", source_bytes=b"x", container=result.container,
        salt_hex=result.salt_hex, nonce_hex=result.nonce_hex,
        dna_length=4, gc_content=0.5,
    )
    log.clear()
    assert log.list_entries() == []
