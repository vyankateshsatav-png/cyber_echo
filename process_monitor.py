"""Records running Windows processes in process_events.

A process is identified by (pid, start time). When a process stops, its row is
marked ENDED. Including the start time means a reused PID is treated as a new
process, so old rows are not left as RUNNING by mistake.

Limitation: a process that starts and stops between two scans is not recorded.
"""

import os
import sqlite3
import time
from datetime import datetime

import psutil

DATABASE = os.environ.get(
    "CYBER_ECHO_DATABASE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyber_echo.db"),
)
SCAN_INTERVAL = 3
TIME_FMT = "%Y-%m-%d %H:%M:%S"


def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS process_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER NOT NULL,
            process_name TEXT NOT NULL,
            executable_path TEXT,
            username TEXT,
            started_at TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(pid, started_at)
        )
    """)
    conn.commit()
    conn.close()


def _read(getter, default):
    try:
        return getter()
    except (psutil.Error, OSError, ValueError):
        return default


def read_process(process):
    """Return a dict describing the process, or None if it cannot be identified."""
    try:
        created = datetime.fromtimestamp(process.create_time()).strftime(TIME_FMT)
    except (psutil.Error, OSError, ValueError, OverflowError):
        return None
    return {
        "pid": process.pid,
        "name": _read(process.name, "Unknown"),
        "executable": _read(process.exe, "Access denied"),
        "username": _read(process.username, "Unknown"),
        "started_at": created,
    }


def ended_ids(running, active_keys):
    """running maps (pid, started_at) -> row id for rows marked RUNNING.
    Return the row ids whose process is no longer active."""
    return [row_id for key, row_id in running.items() if key not in active_keys]


def load_state(conn):
    known = {(row[0], row[1]) for row in conn.execute(
        "SELECT pid, started_at FROM process_events")}
    running = {(row[1], row[2]): row[0] for row in conn.execute(
        "SELECT id, pid, started_at FROM process_events WHERE status = 'RUNNING'")}
    return known, running


def scan_once(conn, known, running):
    """Insert processes not seen before. Returns (active_keys, new_count)."""
    now = datetime.now().strftime(TIME_FMT)
    active = set()
    new_count = 0
    for process in psutil.process_iter():
        info = read_process(process)
        if info is None:
            continue
        key = (info["pid"], info["started_at"])
        active.add(key)
        if key in known:
            continue
        cursor = conn.execute(
            """INSERT INTO process_events
               (pid, process_name, executable_path, username, started_at,
                first_seen, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 'RUNNING', ?)""",
            (info["pid"], info["name"], info["executable"], info["username"],
             info["started_at"], now, now),
        )
        known.add(key)
        running[key] = cursor.lastrowid
        new_count += 1
    return active, new_count


def mark_ended(conn, running, active):
    finished = ended_ids(running, active)
    for row_id in finished:
        conn.execute("UPDATE process_events SET status = 'ENDED' WHERE id = ?", (row_id,))
    for key in [item for item in running if item not in active]:
        del running[key]
    return len(finished)


def main():
    init_db()

    print()
    print("==========================================")
    print("       CYBER ECHO PROCESS MONITOR")
    print("==========================================")
    print("Monitoring running Windows processes")
    print(f"Scan interval: {SCAN_INTERVAL} seconds")
    print("Press CTRL+C to stop.")
    print()

    conn = sqlite3.connect(DATABASE, timeout=10)
    known, running = load_state(conn)
    try:
        while True:
            try:
                active, new_count = scan_once(conn, known, running)
                ended = mark_ended(conn, running, active)
                conn.commit()
                if new_count or ended:
                    print(f"New processes recorded: {new_count}   Processes ended: {ended}")
            except sqlite3.Error as error:
                conn.rollback()
                known, running = load_state(conn)  # resync memory with the database
                print(f"[DATABASE WARNING] {error}")
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print()
        print("CYBER ECHO process monitor stopped.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
