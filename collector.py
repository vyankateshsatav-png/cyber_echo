import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime


DATABASE = os.environ.get(
    "CYBER_ECHO_DATABASE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyber_echo.db"),
)


# =========================================================
# DATABASE
# =========================================================

def init_db():

    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id TEXT UNIQUE,
            event_id INTEGER,
            event_type TEXT,
            description TEXT,
            user_name TEXT,
            source_ip TEXT,
            source_port TEXT,
            workstation_name TEXT,
            logon_type TEXT,
            authentication_package TEXT,
            risk INTEGER,
            created_at TEXT
        )
    """)

    # Add columns if this database was created by an older
    # version of CYBER ECHO.
    existing_columns = {
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(security_events)"
        ).fetchall()
    }

    new_columns = {
        "source_port": "TEXT",
        "workstation_name": "TEXT",
        "logon_type": "TEXT",
        "authentication_package": "TEXT",
    }

    for column, datatype in new_columns.items():

        if column not in existing_columns:

            conn.execute(
                f"""
                ALTER TABLE security_events
                ADD COLUMN {column} {datatype}
                """
            )

    conn.commit()
    conn.close()


# =========================================================
# DATE
# =========================================================

def normalize_date(value):

    if not value:
        return datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    value = str(value).strip()

    try:

        return datetime.strptime(
            value[:19],
            "%Y-%m-%d %H:%M:%S"
        ).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except ValueError:

        pass

    # Old PowerShell JSON date format
    match = re.search(
        r"/Date\((\d+)",
        value
    )

    if match:

        milliseconds = int(
            match.group(1)
        )

        timestamp = milliseconds / 1000

        return datetime.fromtimestamp(
            timestamp
        ).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


# =========================================================
# POWERSHELL
# =========================================================

def run_powershell():

    command = r"""
$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4624,4625
    StartTime=(Get-Date).AddHours(-24)
} | ForEach-Object {

    [PSCustomObject]@{
        RecordId = $_.RecordId
        Id = $_.Id
        TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        Message = $_.Message
    }
}

if ($events) {
    $events | ConvertTo-Json -Compress -Depth 4
}
"""

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60
        )

    except subprocess.TimeoutExpired:

        print("PowerShell timed out.")

        return []

    except Exception as error:

        print(
            f"PowerShell error: {error}"
        )

        return []

    if result.returncode != 0:

        print()
        print(
            "ERROR READING WINDOWS SECURITY LOG:"
        )
        print(result.stderr)

        return []

    output = result.stdout.strip()

    if not output:

        return []

    try:

        data = json.loads(output)

        if isinstance(data, dict):

            data = [data]

        return data

    except json.JSONDecodeError as error:

        print(
            "Could not parse Windows event data."
        )
        print(error)

        return []


# =========================================================
# GENERIC FIELD
# =========================================================

def extract_value(message, label):

    if not message:
        return None

    pattern = (
        rf"{re.escape(label)}"
        rf"\s*:\s*(.*)"
    )

    match = re.search(
        pattern,
        message,
        re.IGNORECASE
    )

    if not match:
        return None

    value = match.group(1).splitlines()[0].strip()

    if value in {
        "",
        "-",
        "NULL"
    }:
        return None

    return value


# =========================================================
# ACCOUNT NAME
# =========================================================

def extract_account_name(
    message,
    event_id
):

    if not message:
        return "Unknown"

    # For a successful logon, prefer the
    # "New Logon" account.
    if event_id == 4624:

        match = re.search(
            r"New Logon:.*?"
            r"Account Name:\s*(.+)",
            message,
            re.IGNORECASE |
            re.DOTALL
        )

        if match:

            value = (
                match.group(1)
                .splitlines()[0]
                .strip()
            )

            if value and value != "-":
                return value

    # For a failed logon, prefer the
    # failed-account section.
    if event_id == 4625:

        match = re.search(
            r"Account For Which Logon Failed:.*?"
            r"Account Name:\s*(.+)",
            message,
            re.IGNORECASE |
            re.DOTALL
        )

        if match:

            value = (
                match.group(1)
                .splitlines()[0]
                .strip()
            )

            if value and value != "-":
                return value

    # Fallback
    return (
        extract_value(
            message,
            "Account Name"
        )
        or "Unknown"
    )


# =========================================================
# LOGON TYPE
# =========================================================

def get_logon_type(
    message,
    event_id
):

    if event_id not in {
        4624,
        4625
    }:
        return "N/A"

    value = extract_value(
        message,
        "Logon Type"
    )

    if not value:
        return "Unknown"

    mappings = {
        "2": "Interactive",
        "3": "Network",
        "4": "Batch",
        "5": "Service",
        "7": "Unlock",
        "8": "NetworkCleartext",
        "9": "NewCredentials",
        "10": "RemoteInteractive",
        "11": "CachedInteractive",
    }

    return (
        mappings.get(
            value,
            f"Type {value}"
        )
    )


# =========================================================
# RISK
# =========================================================

def calculate_risk(
    event_id,
    message
):

    if event_id == 4625:

        return 20

    if event_id == 4624:

        logon_type = extract_value(
            message,
            "Logon Type"
        )

        if logon_type == "10":

            return 10

        return 0

    return 0


# =========================================================
# SAVE
# =========================================================

def save_events(events):

    conn = sqlite3.connect(
        DATABASE
    )

    new_events = 0
    updated_events = 0

    for event in events:

        record_id = str(
            event.get(
                "RecordId",
                ""
            )
        )

        if not record_id:
            continue

        try:

            event_id = int(
                event.get(
                    "Id",
                    0
                )
            )

        except (
            TypeError,
            ValueError
        ):

            event_id = 0

        message = (
            event.get("Message")
            or ""
        )

        created_at = normalize_date(
            event.get(
                "TimeCreated"
            )
        )

        # ---------------------------------------------
        # Event type
        # ---------------------------------------------

        if event_id == 4624:

            event_type = (
                "Successful Logon"
            )

            description = (
                "Windows reported a "
                "successful logon."
            )

        elif event_id == 4625:

            event_type = (
                "Failed Logon"
            )

            description = (
                "Windows reported a "
                "failed logon."
            )

        else:

            event_type = (
                f"Security Event {event_id}"
            )

            description = (
                "Windows Security event."
            )

        # ---------------------------------------------
        # Details
        # ---------------------------------------------

        user_name = extract_account_name(
            message,
            event_id
        )

        source_ip = (
            extract_value(
                message,
                "Source Network Address"
            )
            or "Local/Unknown"
        )

        source_port = (
            extract_value(
                message,
                "Source Port"
            )
            or "Unknown"
        )

        workstation_name = (
            extract_value(
                message,
                "Workstation Name"
            )
            or "Unknown"
        )

        logon_type = get_logon_type(
            message,
            event_id
        )

        authentication_package = (
            extract_value(
                message,
                "Authentication Package Name"
            )
            or "Unknown"
        )

        risk = calculate_risk(
            event_id,
            message
        )

        # ---------------------------------------------
        # Check existing event
        # ---------------------------------------------

        existing = conn.execute(
            """
            SELECT id
            FROM security_events
            WHERE record_id = ?
            """,
            (
                record_id,
            )
        ).fetchone()

        if existing:

            conn.execute(
                """
                UPDATE security_events

                SET
                    event_id = ?,
                    event_type = ?,
                    description = ?,
                    user_name = ?,
                    source_ip = ?,
                    source_port = ?,
                    workstation_name = ?,
                    logon_type = ?,
                    authentication_package = ?,
                    risk = ?,
                    created_at = ?

                WHERE record_id = ?
                """,
                (
                    event_id,
                    event_type,
                    description,
                    user_name,
                    source_ip,
                    source_port,
                    workstation_name,
                    logon_type,
                    authentication_package,
                    risk,
                    created_at,
                    record_id
                )
            )

            updated_events += 1

        else:

            conn.execute(
                """
                INSERT INTO security_events (
                    record_id,
                    event_id,
                    event_type,
                    description,
                    user_name,
                    source_ip,
                    source_port,
                    workstation_name,
                    logon_type,
                    authentication_package,
                    risk,
                    created_at
                )

                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    record_id,
                    event_id,
                    event_type,
                    description,
                    user_name,
                    source_ip,
                    source_port,
                    workstation_name,
                    logon_type,
                    authentication_package,
                    risk,
                    created_at
                )
            )

            new_events += 1

    conn.commit()
    conn.close()

    return (
        new_events,
        updated_events
    )


# =========================================================
# MAIN
# =========================================================

def main():

    print()
    print("==========================================")
    print("       CYBER ECHO SECURITY COLLECTOR")
    print("==========================================")
    print("Reading REAL Windows Security events")
    print("Time range: Last 24 hours")
    print()

    init_db()

    events = run_powershell()

    if not events:

        print(
            "No readable Windows Security events were returned."
        )

        return

    print(
        f"Windows events found : {len(events)}"
    )

    new_events, updated_events = save_events(
        events
    )

    print(
        f"New events stored    : {new_events}"
    )

    print(
        f"Existing events updated : {updated_events}"
    )

    print()
    print(
        "CYBER ECHO collection complete."
    )
    print()


# =========================================================
# START
# =========================================================

if __name__ == "__main__":
    main()
