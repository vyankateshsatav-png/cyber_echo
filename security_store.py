"""Storage for CYBER ECHO owner-security features.

Uses the same SQLite database as the rest of CYBER ECHO. Tables:

  security_settings     passphrase salt and verifier (the passphrase itself is never stored)
  owner_faces           face features of the enrolled owner photos
  protected_files       registry of files moved into the encrypted vault
  access_requests       unauthorised-user requests and the owner's decisions
  face_checks           history of webcam checks
  threat_notifications  Defender detections that were already emailed
"""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta

from cryptography.fernet import Fernet, InvalidToken

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.environ.get(
    "CYBER_ECHO_DATABASE",
    os.path.join(PROJECT_DIR, "cyber_echo.db"),
)
DATA_DIR = os.environ.get("CYBER_ECHO_DATA_DIR", PROJECT_DIR)
VAULT_DIR = os.path.join(DATA_DIR, "vault")
GRANTED_DIR = os.path.join(DATA_DIR, "granted")
SNAPSHOT_DIR = os.path.join(DATA_DIR, "snapshots")
MODELS_DIR = os.path.join(PROJECT_DIR, "models")

MIN_PASSPHRASE = 12
MAX_WRONG_ATTEMPTS = 5
TIME_FMT = "%Y-%m-%d %H:%M:%S"
TABLES = (
    "security_settings",
    "owner_faces",
    "protected_files",
    "access_requests",
    "face_checks",
    "threat_notifications",
)
_SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1, "dklen": 32, "maxmem": 128 * 1024 * 1024}
_VERIFIER_TEXT = b"CYBER-ECHO-OWNER-OK"

SCHEMA = """
CREATE TABLE IF NOT EXISTS security_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS owner_faces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    features TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS protected_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT UNIQUE NOT NULL,
    file_name TEXT NOT NULL,
    vault_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'LOCKED',
    granted_path TEXT,
    grant_expires_at TEXT,
    added_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    snapshot_path TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    attempts INTEGER NOT NULL DEFAULT 0,
    best_score REAL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT,
    grant_expires_at TEXT,
    decision_note TEXT
);
CREATE TABLE IF NOT EXISTS face_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at TEXT NOT NULL,
    result TEXT NOT NULL,
    best_score REAL,
    face_count INTEGER
);
CREATE TABLE IF NOT EXISTS threat_notifications (
    detection_id TEXT PRIMARY KEY,
    threat_name TEXT,
    notified_at TEXT NOT NULL
);
"""

_schema_ready = False


def connect():
    global _schema_ready
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    if not _schema_ready:
        conn.executescript(SCHEMA)
        _schema_ready = True
    return conn


@contextmanager
def db():
    """Open a connection, commit on success, roll back on error, always close."""
    conn = connect()
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def stamp(moment=None):
    return (moment or datetime.now()).strftime(TIME_FMT)


def row_dict(row):
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}


def rows_as_dicts(rows):
    return [row_dict(row) for row in rows]


def new_token():
    return secrets.token_urlsafe(32)


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ----- Owner passphrase -----

def _derive(passphrase, salt):
    raw = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, **_SCRYPT)
    return base64.urlsafe_b64encode(raw)


def owner_configured():
    with db() as conn:
        row = conn.execute(
            "SELECT 1 FROM security_settings WHERE key = 'owner_salt'"
        ).fetchone()
    return row is not None


def create_passphrase(passphrase):
    if owner_configured():
        raise RuntimeError("The owner passphrase is already set.")
    if not passphrase or len(passphrase) < MIN_PASSPHRASE:
        raise ValueError(
            f"The passphrase must be at least {MIN_PASSPHRASE} characters."
        )
    salt = os.urandom(16)
    verifier = Fernet(_derive(passphrase, salt)).encrypt(_VERIFIER_TEXT).decode("ascii")
    with db() as conn:
        conn.execute(
            "INSERT INTO security_settings (key, value) VALUES ('owner_salt', ?)",
            (salt.hex(),),
        )
        conn.execute(
            "INSERT INTO security_settings (key, value) VALUES ('owner_verifier', ?)",
            (verifier,),
        )


def unlock_key(passphrase):
    """Return the vault key for this passphrase, or None if it is wrong."""
    if not passphrase:
        return None
    with db() as conn:
        rows = conn.execute(
            "SELECT key, value FROM security_settings "
            "WHERE key IN ('owner_salt', 'owner_verifier')"
        ).fetchall()
    values = {row["key"]: row["value"] for row in rows}
    if len(values) != 2:
        return None
    key = _derive(passphrase, bytes.fromhex(values["owner_salt"]))
    try:
        if Fernet(key).decrypt(values["owner_verifier"].encode("ascii")) == _VERIFIER_TEXT:
            return key
    except InvalidToken:
        pass
    return None


def verify_passphrase(passphrase):
    return unlock_key(passphrase) is not None


# ----- Owner face features -----

def replace_owner_features(feature_lists):
    if not feature_lists:
        raise ValueError("No face features were supplied.")
    now = stamp()
    with db() as conn:
        conn.execute("DELETE FROM owner_faces")
        for features in feature_lists:
            conn.execute(
                "INSERT INTO owner_faces (features, created_at) VALUES (?, ?)",
                (json.dumps(features), now),
            )


def get_owner_features():
    with db() as conn:
        rows = conn.execute("SELECT features FROM owner_faces ORDER BY id").fetchall()
    return [json.loads(row["features"]) for row in rows]


# ----- Protected files -----

def add_protected(original_path, file_name, vault_path, digest, size):
    now = stamp()
    with db() as conn:
        cursor = conn.execute(
            """INSERT INTO protected_files
               (original_path, file_name, vault_path, sha256, size, state, added_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 'LOCKED', ?, ?)""",
            (original_path, file_name, vault_path, digest, size, now, now),
        )
        return cursor.lastrowid


def delete_protected(file_id):
    with db() as conn:
        conn.execute("DELETE FROM protected_files WHERE id = ?", (file_id,))


def get_protected(file_id):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM protected_files WHERE id = ?", (file_id,)
        ).fetchone()
    return row_dict(row)


def find_protected_by_path(path):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM protected_files WHERE original_path = ?", (path,)
        ).fetchone()
    return row_dict(row)


def list_protected():
    with db() as conn:
        rows = conn.execute("SELECT * FROM protected_files ORDER BY id").fetchall()
    return rows_as_dicts(rows)


def list_granted():
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM protected_files WHERE state = 'GRANTED'"
        ).fetchall()
    return rows_as_dicts(rows)


def list_expired_grants(now_text):
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM protected_files "
            "WHERE state = 'GRANTED' AND grant_expires_at <= ?",
            (now_text,),
        ).fetchall()
    return rows_as_dicts(rows)


def set_granted(file_id, granted_path, expires_text):
    with db() as conn:
        conn.execute(
            """UPDATE protected_files
               SET state = 'GRANTED', granted_path = ?, grant_expires_at = ?, updated_at = ?
               WHERE id = ?""",
            (granted_path, expires_text, stamp(), file_id),
        )


def set_locked(file_id):
    with db() as conn:
        conn.execute(
            """UPDATE protected_files
               SET state = 'LOCKED', granted_path = NULL, grant_expires_at = NULL, updated_at = ?
               WHERE id = ?""",
            (stamp(), file_id),
        )


# ----- Owner access requests -----

def create_request(token_digest, snapshot_path, ttl_hours, best_score):
    now = datetime.now()
    with db() as conn:
        cursor = conn.execute(
            """INSERT INTO access_requests
               (token_hash, snapshot_path, status, attempts, best_score, created_at, expires_at)
               VALUES (?, ?, 'PENDING', 0, ?, ?, ?)""",
            (
                token_digest,
                snapshot_path,
                best_score,
                stamp(now),
                stamp(now + timedelta(hours=ttl_hours)),
            ),
        )
        return cursor.lastrowid


def find_pending(token):
    with db() as conn:
        row = conn.execute(
            """SELECT * FROM access_requests
               WHERE token_hash = ? AND status = 'PENDING' AND expires_at > ?""",
            (hash_token(token), stamp()),
        ).fetchone()
    return row_dict(row)


def get_request(request_id):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM access_requests WHERE id = ?", (request_id,)
        ).fetchone()
    return row_dict(row)


def increment_attempts(request_id):
    with db() as conn:
        conn.execute(
            "UPDATE access_requests SET attempts = attempts + 1 WHERE id = ?",
            (request_id,),
        )
        row = conn.execute(
            "SELECT attempts FROM access_requests WHERE id = ?", (request_id,)
        ).fetchone()
    return row["attempts"]


def finish_request(request_id, status, note, grant_expires=None):
    with db() as conn:
        conn.execute(
            """UPDATE access_requests
               SET status = ?, decided_at = ?, decision_note = ?, grant_expires_at = ?
               WHERE id = ?""",
            (status, stamp(), note, grant_expires, request_id),
        )


def expire_old_requests():
    now = stamp()
    with db() as conn:
        conn.execute(
            """UPDATE access_requests SET status = 'EXPIRED', decided_at = ?
               WHERE status = 'PENDING' AND expires_at <= ?""",
            (now, now),
        )


def pending_exists():
    with db() as conn:
        row = conn.execute(
            """SELECT 1 FROM access_requests
               WHERE status = 'PENDING' AND expires_at > ? LIMIT 1""",
            (stamp(),),
        ).fetchone()
    return row is not None


def last_request_time():
    with db() as conn:
        row = conn.execute("SELECT MAX(created_at) AS last FROM access_requests").fetchone()
    return datetime.strptime(row["last"], TIME_FMT) if row["last"] else None


def approved_grant_active():
    with db() as conn:
        row = conn.execute(
            """SELECT 1 FROM access_requests
               WHERE status = 'APPROVED' AND grant_expires_at > ? LIMIT 1""",
            (stamp(),),
        ).fetchone()
    return row is not None


def list_requests(limit=20):
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM access_requests ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return rows_as_dicts(rows)


# ----- Face check history -----

def log_face_check(result, best_score, face_count):
    with db() as conn:
        conn.execute(
            "INSERT INTO face_checks (checked_at, result, best_score, face_count) "
            "VALUES (?, ?, ?, ?)",
            (stamp(), result, best_score, face_count),
        )


def list_face_checks(limit=20):
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM face_checks ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return rows_as_dicts(rows)


# ----- Threat notifications -----

def threat_seen(detection_id):
    with db() as conn:
        row = conn.execute(
            "SELECT 1 FROM threat_notifications WHERE detection_id = ?",
            (detection_id,),
        ).fetchone()
    return row is not None


def mark_threat_seen(detection_id, threat_name):
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO threat_notifications "
            "(detection_id, threat_name, notified_at) VALUES (?, ?, ?)",
            (detection_id, threat_name or "", stamp()),
        )


def count_threats_seen():
    with db() as conn:
        return conn.execute("SELECT COUNT(*) FROM threat_notifications").fetchone()[0]
