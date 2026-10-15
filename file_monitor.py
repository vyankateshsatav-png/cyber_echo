import os
import sqlite3
import time
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


DATABASE = os.environ.get(
    "CYBER_ECHO_DATABASE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyber_echo.db"),
)

# The CYBER_ECHO project folder itself must NOT be monitored.
PROJECT_DIR = os.path.abspath(
    os.path.dirname(__file__)
)

HOME = os.path.expanduser("~")

WATCH_FOLDERS = [
    os.path.join(HOME, "Desktop"),
    os.path.join(HOME, "Downloads"),
    os.path.join(HOME, "Documents"),
]


# =========================================================
# FILES / FOLDERS TO IGNORE
# =========================================================

IGNORED_NAMES = {
    "cyber_echo.db",
    "cyber_echo.db-journal",
    "cyber_echo.db-wal",
    "cyber_echo.db-shm",
}

IGNORED_DIRECTORIES = {
    "__pycache__",
    ".git",
}


def should_ignore(path):

    path = os.path.abspath(path)

    # Never monitor our own project
    try:
        if os.path.commonpath([
            path,
            PROJECT_DIR
        ]) == PROJECT_DIR:
            return True
    except ValueError:
        pass

    name = os.path.basename(path).lower()

    # Ignore our database and SQLite support files
    if name in {
        item.lower()
        for item in IGNORED_NAMES
    }:
        return True

    # Ignore Python cache folders
    parts = [
        part.lower()
        for part in path.split(os.sep)
    ]

    for directory in IGNORED_DIRECTORIES:
        if directory.lower() in parts:
            return True

    return False


# =========================================================
# DATABASE
# =========================================================

def init_db():

    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS file_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_name TEXT NOT NULL,
            extension TEXT,
            risk INTEGER NOT NULL,
            reason TEXT,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# =========================================================
# FILE RISK
# =========================================================

def calculate_file_risk(file_path, event_type):

    extension = os.path.splitext(
        file_path
    )[1].lower()

    path_lower = file_path.lower()

    risk = 0
    reasons = []

    executable_extensions = {
        ".exe",
        ".dll",
        ".msi",
        ".scr",
        ".com"
    }

    script_extensions = {
        ".ps1",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".jse",
        ".wsf",
        ".hta"
    }

    temp_locations = [
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\"
    ]

    if extension in executable_extensions:

        risk += 15

        reasons.append(
            "Executable file activity detected"
        )

    if extension in script_extensions:

        risk += 10

        reasons.append(
            "Script file activity detected"
        )

    for location in temp_locations:

        if location in path_lower:

            risk += 10

            reasons.append(
                "File is located in a temporary directory"
            )

            break

    if event_type == "deleted":

        risk += 5

        reasons.append(
            "File was deleted"
        )

    return min(risk, 40), reasons


# =========================================================
# SAVE EVENT
# =========================================================

def save_file_event(event_type, file_path):

    if should_ignore(file_path):
        return

    if not file_path:
        return

    if os.path.isdir(file_path):
        return

    file_name = os.path.basename(file_path)

    extension = os.path.splitext(
        file_name
    )[1].lower()

    risk, reasons = calculate_file_risk(
        file_path,
        event_type
    )

    reason = "; ".join(reasons)

    created_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn = sqlite3.connect(DATABASE)

    try:

        conn.execute("""
            INSERT INTO file_events (
                event_type,
                file_path,
                file_name,
                extension,
                risk,
                reason,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event_type,
            os.path.abspath(file_path),
            file_name,
            extension,
            risk,
            reason,
            created_at
        ))

        conn.commit()

    except sqlite3.Error as error:

        print(
            f"[DATABASE WARNING] {error}"
        )

    finally:

        conn.close()


# =========================================================
# FILE EVENT HANDLER
# =========================================================

class CyberEchoFileHandler(
    FileSystemEventHandler
):

    def on_created(self, event):

        if event.is_directory:
            return

        if should_ignore(event.src_path):
            return

        print(
            f"[FILE CREATED] {event.src_path}"
        )

        save_file_event(
            "created",
            event.src_path
        )


    def on_modified(self, event):

        if event.is_directory:
            return

        if should_ignore(event.src_path):
            return

        save_file_event(
            "modified",
            event.src_path
        )


    def on_deleted(self, event):

        if event.is_directory:
            return

        if should_ignore(event.src_path):
            return

        print(
            f"[FILE DELETED] {event.src_path}"
        )

        save_file_event(
            "deleted",
            event.src_path
        )


    def on_moved(self, event):

        if event.is_directory:
            return

        if should_ignore(event.dest_path):
            return

        print(
            f"[FILE MOVED] "
            f"{event.src_path}"
            f" -> "
            f"{event.dest_path}"
        )

        save_file_event(
            "moved",
            event.dest_path
        )


# =========================================================
# MAIN
# =========================================================

def main():

    print()
    print("==========================================")
    print("        CYBER ECHO FILE MONITOR")
    print("==========================================")
    print("Monitoring REAL file activity")
    print()

    init_db()

    observer = Observer()

    handler = CyberEchoFileHandler()

    active_folders = 0

    for folder in WATCH_FOLDERS:

        if not os.path.isdir(folder):

            print(
                f"[NOT FOUND] {folder}"
            )

            continue

        # -------------------------------------------------
        # Important:
        # watchdog still watches Desktop recursively,
        # but our handler ignores CYBER_ECHO itself.
        # -------------------------------------------------

        observer.schedule(
            handler,
            folder,
            recursive=True
        )

        print(
            f"[MONITORING] {folder}"
        )

        active_folders += 1

    print()

    if active_folders == 0:

        print(
            "No folders could be monitored."
        )

        return

    observer.start()

    print(
        "CYBER ECHO file monitoring is ACTIVE."
    )

    print(
        "CYBER_ECHO project files are excluded."
    )

    print(
        "SQLite database files are excluded."
    )

    print(
        "Press CTRL+C to stop."
    )

    print()

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        print()
        print("Stopping file monitor...")

        observer.stop()

    observer.join()

    print(
        "CYBER ECHO file monitor stopped."
    )


# =========================================================
# START
# =========================================================

if __name__ == "__main__":
    main()