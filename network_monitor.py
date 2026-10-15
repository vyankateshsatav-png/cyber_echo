import sqlite3
import os
import time
from datetime import datetime

import psutil


DATABASE = os.environ.get(
    "CYBER_ECHO_DATABASE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyber_echo.db"),
)
SCAN_INTERVAL = 5


# =========================================================
# DATABASE
# =========================================================

def init_db():

    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER,
            process_name TEXT,
            executable_path TEXT,
            username TEXT,
            local_ip TEXT,
            local_port INTEGER,
            remote_ip TEXT,
            remote_port INTEGER,
            status TEXT,
            protocol TEXT,
            first_seen TEXT,
            last_seen TEXT,
            created_at TEXT,
            UNIQUE(
                pid,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                protocol
            )
        )
    """)

    conn.commit()
    conn.close()


# =========================================================
# GET PROCESS DETAILS
# =========================================================

def get_process_details(pid):

    if pid is None or pid <= 0:
        return "Unknown", "Unknown", "Unknown"

    try:

        process = psutil.Process(pid)

        try:
            name = process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            name = "Unknown"

        try:
            path = process.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            path = "Access denied"

        try:
            username = process.username()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            username = "Unknown"

        return name, path, username

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        OSError
    ):
        return "Unknown", "Unknown", "Unknown"


# =========================================================
# SAVE CONNECTION
# =========================================================

def save_connection(connection):

    pid = connection.pid

    if pid is None:
        return False

    # -----------------------------------------------------
    # Local address
    # -----------------------------------------------------

    if not connection.laddr:
        return False

    local_ip = connection.laddr.ip
    local_port = connection.laddr.port

    # -----------------------------------------------------
    # Remote address
    # -----------------------------------------------------

    if connection.raddr:

        remote_ip = connection.raddr.ip
        remote_port = connection.raddr.port

    else:

        remote_ip = None
        remote_port = None

    # Ignore loopback traffic.
    if remote_ip in {
        None,
        "",
        "127.0.0.1",
        "::1"
    }:

        return False

    process_name, executable_path, username = (
        get_process_details(pid)
    )

    protocol = "TCP"

    if connection.type == 2:
        protocol = "UDP"

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn = sqlite3.connect(DATABASE)

    try:

        existing = conn.execute("""
            SELECT id
            FROM network_events

            WHERE pid = ?
              AND local_ip = ?
              AND local_port = ?
              AND remote_ip = ?
              AND remote_port = ?
              AND protocol = ?
        """, (
            pid,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol
        )).fetchone()

        if existing:

            conn.execute("""
                UPDATE network_events

                SET
                    last_seen = ?,
                    status = ?

                WHERE id = ?
            """, (
                now,
                connection.status,
                existing[0]
            ))

            conn.commit()

            return False

        conn.execute("""
            INSERT INTO network_events (

                pid,
                process_name,
                executable_path,
                username,

                local_ip,
                local_port,

                remote_ip,
                remote_port,

                status,
                protocol,

                first_seen,
                last_seen,
                created_at

            )

            VALUES (
                ?, ?, ?, ?,
                ?, ?,
                ?, ?,
                ?, ?,
                ?, ?, ?
            )
        """, (
            pid,
            process_name,
            executable_path,
            username,

            local_ip,
            local_port,

            remote_ip,
            remote_port,

            connection.status,
            protocol,

            now,
            now,
            now
        ))

        conn.commit()

        return True

    except sqlite3.IntegrityError:

        return False

    except sqlite3.Error as error:

        print(
            f"[DATABASE ERROR] {error}"
        )

        return False

    finally:

        conn.close()


# =========================================================
# SCAN NETWORK CONNECTIONS
# =========================================================

def scan_connections():

    new_connections = 0

    try:

        connections = psutil.net_connections(
            kind="inet"
        )

    except psutil.AccessDenied:

        print(
            "[NETWORK ERROR] Access denied. "
            "Run VS Code as Administrator."
        )

        return 0

    except Exception as error:

        print(
            f"[NETWORK ERROR] {error}"
        )

        return 0

    for connection in connections:

        try:

            if save_connection(
                connection
            ):

                new_connections += 1

                if connection.raddr:

                    remote = (
                        f"{connection.raddr.ip}:"
                        f"{connection.raddr.port}"
                    )

                else:

                    remote = "Unknown"

                print(
                    f"[NEW CONNECTION] "
                    f"PID {connection.pid} "
                    f"→ {remote}"
                )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            OSError
        ):

            continue

        except Exception as error:

            print(
                f"[WARNING] Connection inspection failed: "
                f"{error}"
            )

    return new_connections


# =========================================================
# MAIN
# =========================================================

def main():

    print()
    print("==========================================")
    print("       CYBER ECHO NETWORK MONITOR")
    print("==========================================")
    print()
    print("Monitoring REAL network connections")
    print(f"Scan interval: {SCAN_INTERVAL} seconds")
    print()
    print("Loopback connections are ignored.")
    print("Press CTRL+C to stop.")
    print()

    init_db()

    try:

        while True:

            new_connections = (
                scan_connections()
            )

            if new_connections:

                print(
                    f"New network connections recorded: "
                    f"{new_connections}"
                )

            else:

                print(
                    "No new external network connections."
                )

            time.sleep(
                SCAN_INTERVAL
            )

    except KeyboardInterrupt:

        print()
        print(
            "CYBER ECHO network monitor stopped."
        )


# =========================================================
# START
# =========================================================

if __name__ == "__main__":
    main()
