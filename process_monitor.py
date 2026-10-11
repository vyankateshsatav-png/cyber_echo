import sqlite3
import os
import time
from datetime import datetime

import psutil


DATABASE = os.environ.get(
    "CYBER_ECHO_DATABASE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyber_echo.db"),
)
SCAN_INTERVAL = 3


# =========================================================
# DATABASE
# =========================================================

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


# =========================================================
# GET PROCESS INFORMATION
# =========================================================

def get_process_information(process):

    try:
        pid = process.pid

        try:
            name = process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            name = "Unknown"

        try:
            executable = process.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            executable = "Access denied"

        try:
            username = process.username()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            username = "Unknown"

        try:
            create_time = process.create_time()

            started_at = datetime.fromtimestamp(
                create_time
            ).strftime("%Y-%m-%d %H:%M:%S")

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            OSError,
            ValueError
        ):
            started_at = "Unknown"

        return {
            "pid": pid,
            "name": name,
            "executable": executable,
            "username": username,
            "started_at": started_at
        }

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        OSError
    ):
        return None


# =========================================================
# SAVE PROCESS
# =========================================================

def save_process(info):

    if info is None:
        return False

    # We cannot reliably identify a process with an unknown
    # start time, so don't store those.
    if info["started_at"] == "Unknown":
        return False

    conn = sqlite3.connect(DATABASE)

    try:

        cursor = conn.execute("""
            SELECT id
            FROM process_events
            WHERE pid = ?
            AND started_at = ?
        """, (
            info["pid"],
            info["started_at"]
        ))

        existing = cursor.fetchone()

        if existing:
            return False

        now = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        conn.execute("""
            INSERT INTO process_events (
                pid,
                process_name,
                executable_path,
                username,
                started_at,
                first_seen,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            info["pid"],
            info["name"],
            info["executable"],
            info["username"],
            info["started_at"],
            now,
            "RUNNING",
            now
        ))

        conn.commit()

        return True

    except sqlite3.IntegrityError:
        # Another scan may have inserted it already.
        return False

    except sqlite3.Error as error:
        print(f"Database error: {error}")
        return False

    finally:
        conn.close()


# =========================================================
# SCAN PROCESSES
# =========================================================

def scan_processes():

    new_processes = 0
    active_pids = set()

    for process in psutil.process_iter():

        try:
            active_pids.add(process.pid)

            info = get_process_information(process)

            if info is None:
                continue

            if save_process(info):

                new_processes += 1

                print(
                    f"[NEW PROCESS] "
                    f"{info['name']} "
                    f"(PID {info['pid']})"
                )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            OSError
        ):
            continue

        except Exception as error:
            print(
                f"[WARNING] Could not inspect process: "
                f"{error}"
            )

    return active_pids, new_processes


# =========================================================
# MARK FINISHED PROCESSES
# =========================================================

def update_finished_processes(active_pids):

    conn = sqlite3.connect(DATABASE)

    finished = 0

    try:

        rows = conn.execute("""
            SELECT id, pid
            FROM process_events
            WHERE status = 'RUNNING'
        """).fetchall()

        for event_id, pid in rows:

            if pid not in active_pids:

                conn.execute("""
                    UPDATE process_events
                    SET status = 'ENDED'
                    WHERE id = ?
                """, (
                    event_id,
                ))

                finished += 1

        conn.commit()

    except sqlite3.Error as error:

        print(
            f"[WARNING] Database update failed: {error}"
        )

    finally:

        conn.close()

    return finished


# =========================================================
# MAIN MONITOR
# =========================================================

def main():

    print()
    print("==========================================")
    print("       CYBER ECHO PROCESS MONITOR")
    print("==========================================")
    print("Monitoring REAL Windows processes")
    print(f"Scan interval: {SCAN_INTERVAL} seconds")
    print()
    print("Press CTRL+C to stop.")
    print()

    init_db()

    try:

        while True:

            active_pids, new_processes = scan_processes()

            finished_processes = (
                update_finished_processes(
                    active_pids
                )
            )

            if new_processes:

                print(
                    f"New processes recorded: "
                    f"{new_processes}"
                )

            if finished_processes:

                print(
                    f"Processes ended: "
                    f"{finished_processes}"
                )

            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:

        print()
        print("CYBER ECHO process monitor stopped.")
        print()


# =========================================================
# START
# =========================================================

if __name__ == "__main__":
    main()
