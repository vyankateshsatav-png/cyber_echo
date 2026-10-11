import hashlib
import os
import ipaddress
import sqlite3
from datetime import datetime, timedelta


DATABASE = os.environ.get(
    "CYBER_ECHO_DATABASE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyber_echo.db"),
)

INCIDENT_WINDOW_MINUTES = 10
TRIGGER_MERGE_MINUTES = 5


# =========================================================
# THINGS THAT SHOULD NEVER BECOME THREATS BY THEMSELVES
# =========================================================

IGNORED_FILE_NAMES = {
    "cyber_echo.db",
    "cyber_echo.db-journal",
    "cyber_echo.db-wal",
    "cyber_echo.db-shm",
}


# These are potentially interesting process names.
# They are NOT automatically treated as malware.
SUSPICIOUS_PROCESS_NAMES = {
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
}


# =========================================================
# DATABASE
# =========================================================

def init_db():

    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS correlation_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT UNIQUE,
            alert_level TEXT NOT NULL,
            score INTEGER NOT NULL,
            title TEXT NOT NULL,
            explanation TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            first_event_time TEXT NOT NULL,
            last_event_time TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Support older CYBER ECHO databases.
    existing_columns = {
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(correlation_alerts)"
        ).fetchall()
    }

    if "fingerprint" not in existing_columns:
        conn.execute(
            """
            ALTER TABLE correlation_alerts
            ADD COLUMN fingerprint TEXT
            """
        )

    conn.commit()
    conn.close()


# =========================================================
# TIME
# =========================================================

def parse_time(value):

    if not value:
        return None

    value = str(value).strip()

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ]

    for fmt in formats:

        try:
            return datetime.strptime(
                value[:26],
                fmt
            )

        except ValueError:
            continue

    return None


# =========================================================
# LOAD SECURITY EVENTS
# =========================================================

def load_security_events():

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    try:

        rows = conn.execute("""
            SELECT
                id,
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
            FROM security_events
            ORDER BY created_at ASC
        """).fetchall()

    except sqlite3.Error as error:

        print(
            f"[DATABASE WARNING] Security events: {error}"
        )

        # Fallback for an older database schema.
        try:

            rows = conn.execute("""
                SELECT
                    id,
                    event_id,
                    event_type,
                    description,
                    user_name,
                    source_ip,
                    risk,
                    created_at
                FROM security_events
                ORDER BY created_at ASC
            """).fetchall()

        except sqlite3.Error:
            rows = []

    conn.close()

    return rows


# =========================================================
# LOAD PROCESS EVENTS
# =========================================================

def load_process_events():

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    try:

        rows = conn.execute("""
            SELECT
                id,
                pid,
                process_name,
                executable_path,
                username,
                status,
                created_at
            FROM process_events
            ORDER BY created_at ASC
        """).fetchall()

    except sqlite3.Error as error:

        print(
            f"[DATABASE WARNING] Process events: {error}"
        )

        rows = []

    conn.close()

    return rows


# =========================================================
# LOAD FILE EVENTS
# =========================================================

def load_file_events():

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    try:

        rows = conn.execute("""
            SELECT
                id,
                event_type,
                file_path,
                file_name,
                extension,
                risk,
                reason,
                created_at
            FROM file_events
            ORDER BY created_at ASC
        """).fetchall()

    except sqlite3.Error as error:

        print(
            f"[DATABASE WARNING] File events: {error}"
        )

        rows = []

    conn.close()

    return rows


# =========================================================
# LOAD NETWORK EVENTS
# =========================================================

def load_network_events():

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    try:

        rows = conn.execute("""
            SELECT
                id,
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
            FROM network_events
            ORDER BY created_at ASC
        """).fetchall()

    except sqlite3.Error as error:

        print(
            f"[DATABASE WARNING] Network events: {error}"
        )

        rows = []

    conn.close()

    return rows


# =========================================================
# IP HELPERS
# =========================================================

def normalize_ip(value):

    if not value:
        return None

    value = str(value).strip()

    if value in {
        "",
        "-",
        "Unknown",
        "Local/Unknown",
        "127.0.0.1",
        "::1",
    }:
        return None

    try:

        address = ipaddress.ip_address(
            value
        )

        # Loopback is not a remote threat address.
        if address.is_loopback:
            return None

        return str(address)

    except ValueError:

        return None


def is_public_ip(value):

    normalized = normalize_ip(value)

    if not normalized:
        return False

    try:

        address = ipaddress.ip_address(
            normalized
        )

        return (
            not address.is_private
            and not address.is_loopback
            and not address.is_link_local
            and not address.is_multicast
            and not address.is_reserved
            and not address.is_unspecified
        )

    except ValueError:

        return False


# =========================================================
# PROCESS CLASSIFICATION
# =========================================================

def classify_process(
    process_name,
    executable_path
):

    name = (
        process_name
        or ""
    ).lower()

    path = (
        executable_path
        or ""
    ).lower()

    suspicious = False

    reasons = []

    if name in SUSPICIOUS_PROCESS_NAMES:

        suspicious = True

        reasons.append(
            "system scripting/execution utility"
        )

    suspicious_locations = [
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
    ]

    for location in suspicious_locations:

        if location in path:

            suspicious = True

            reasons.append(
                "executable is in a user-writable location"
            )

            break

    return suspicious, reasons


# =========================================================
# BUILD COMMON TIMELINE
# =========================================================

def build_events():

    events = []

    # -----------------------------------------------------
    # SECURITY EVENTS
    # -----------------------------------------------------

    for row in load_security_events():

        event_time = parse_time(
            row["created_at"]
        )

        if event_time is None:
            continue

        event_id = row["event_id"]

        if event_id == 4625:

            kind = "failed_login"

        elif event_id == 4624:

            kind = "successful_login"

        else:

            kind = "security_event"

        source_ip = None

        if "source_ip" in row.keys():

            source_ip = normalize_ip(
                row["source_ip"]
            )

        details = (
            f"Event ID: {event_id} | "
            f"User: {row['user_name']} | "
            f"Source IP: "
            f"{row['source_ip']}"
        )

        if "source_port" in row.keys():

            details += (
                f" | Source Port: "
                f"{row['source_port']}"
            )

        if "workstation_name" in row.keys():

            details += (
                f" | Workstation: "
                f"{row['workstation_name']}"
            )

        if "logon_type" in row.keys():

            details += (
                f" | Logon Type: "
                f"{row['logon_type']}"
            )

        events.append({

            "source": "Windows Security",

            "source_id":
                f"security:{row['id']}",

            "kind": kind,

            "name":
                row["event_type"],

            "description":
                row["description"],

            "time":
                event_time,

            "risk":
                int(row["risk"] or 0),

            "details":
                details,

            "remote_ip":
                source_ip,
        })

    # -----------------------------------------------------
    # PROCESS EVENTS
    # -----------------------------------------------------

    for row in load_process_events():

        event_time = parse_time(
            row["created_at"]
        )

        if event_time is None:
            continue

        suspicious, reasons = classify_process(
            row["process_name"],
            row["executable_path"]
        )

        events.append({

            "source": "Process Monitor",

            "source_id":
                f"process:{row['id']}",

            "kind":
                "suspicious_process"
                if suspicious
                else "process",

            "name":
                row["process_name"]
                or "Unknown",

            "description":
                (
                    f"{row['process_name']} "
                    f"(PID {row['pid']})"
                ),

            "time":
                event_time,

            "risk":
                15
                if suspicious
                else 0,

            "details":
                (
                    f"PID: {row['pid']} | "
                    f"User: {row['username']} | "
                    f"Path: {row['executable_path']}"
                ),

            "suspicious_reasons":
                reasons,
        })

    # -----------------------------------------------------
    # FILE EVENTS
    # -----------------------------------------------------

    for row in load_file_events():

        filename = (
            row["file_name"]
            or ""
        ).lower()

        if filename in {
            name.lower()
            for name in IGNORED_FILE_NAMES
        }:
            continue

        event_time = parse_time(
            row["created_at"]
        )

        if event_time is None:
            continue

        risk = int(
            row["risk"] or 0
        )

        events.append({

            "source": "File Monitor",

            "source_id":
                f"file:{row['id']}",

            "kind":
                "suspicious_file"
                if risk > 0
                else "file",

            "name":
                row["file_name"],

            "description":
                (
                    f"File {row['event_type']}: "
                    f"{row['file_name']}"
                ),

            "time":
                event_time,

            "risk":
                risk,

            "details":
                (
                    f"Path: {row['file_path']} | "
                    f"Reason: "
                    f"{row['reason'] or 'None'}"
                ),
        })

    # -----------------------------------------------------
    # NETWORK EVENTS
    # -----------------------------------------------------

    for row in load_network_events():

        event_time = parse_time(
            row["created_at"]
        )

        if event_time is None:
            continue

        remote_ip = normalize_ip(
            row["remote_ip"]
        )

        if not remote_ip:
            continue

        process_name = (
            row["process_name"]
            or "Unknown"
        )

        executable_path = (
            row["executable_path"]
            or ""
        )

        suspicious, reasons = classify_process(
            process_name,
            executable_path
        )

        # Normal network connections are observations.
        # They do NOT become alerts simply because they
        # exist.

        if suspicious:

            kind = "suspicious_network"

            risk = 10

        else:

            kind = "network"

            risk = 0

        events.append({

            "source": "Network Monitor",

            "source_id":
                f"network:{row['id']}",

            "kind":
                kind,

            "name":
                (
                    f"{process_name} → "
                    f"{remote_ip}"
                ),

            "description":
                (
                    f"{process_name} "
                    f"connected to "
                    f"{remote_ip}:"
                    f"{row['remote_port']}"
                ),

            "time":
                event_time,

            "risk":
                risk,

            "remote_ip":
                remote_ip,

            "details":
                (
                    f"PID: {row['pid']} | "
                    f"Protocol: {row['protocol']} | "
                    f"Local: {row['local_ip']}:"
                    f"{row['local_port']} | "
                    f"Remote: {remote_ip}:"
                    f"{row['remote_port']} | "
                    f"Status: {row['status']} | "
                    f"Path: "
                    f"{row['executable_path']}"
                ),

            "public_ip":
                is_public_ip(remote_ip),
        })

    events.sort(
        key=lambda event: event["time"]
    )

    return events


# =========================================================
# TRIGGERS
# =========================================================

def is_trigger(event):

    return event["kind"] in {
        "failed_login",
        "suspicious_process",
        "suspicious_file",
        "suspicious_network",
    }


def build_triggers(events):

    triggers = []

    for event in events:

        if not is_trigger(event):
            continue

        if triggers:

            previous = triggers[-1]

            if (
                event["time"]
                - previous["time"]
                <= timedelta(
                    minutes=TRIGGER_MERGE_MINUTES
                )
            ):

                # Keep the stronger trigger.
                if (
                    event["risk"]
                    > previous["risk"]
                ):

                    triggers[-1] = event

                continue

        triggers.append(event)

    return triggers


# =========================================================
# BUILD INCIDENT
# =========================================================

def build_incident(
    trigger,
    events
):

    half_window = (
        timedelta(
            minutes=
            INCIDENT_WINDOW_MINUTES / 2
        )
    )

    start = (
        trigger["time"]
        - half_window
    )

    end = (
        trigger["time"]
        + half_window
    )

    related = []

    for event in events:

        if (
            start
            <= event["time"]
            <= end
        ):

            related.append(event)

    return related


# =========================================================
# INCIDENT ANALYSIS
# =========================================================

def analyze_incident(events):

    if not events:
        return None

    failed_logins = [
        event
        for event in events
        if event["kind"] == "failed_login"
    ]

    suspicious_processes = [
        event
        for event in events
        if event["kind"] == "suspicious_process"
    ]

    suspicious_files = [
        event
        for event in events
        if event["kind"] == "suspicious_file"
    ]

    suspicious_network = [
        event
        for event in events
        if event["kind"] == "suspicious_network"
    ]

    network_events = [
        event
        for event in events
        if event["kind"]
        in {
            "network",
            "suspicious_network"
        }
    ]

    sources = {
        event["source"]
        for event in events
    }

    score = 0
    reasons = []

    # -----------------------------------------------------
    # Failed authentication
    # -----------------------------------------------------

    if len(failed_logins) == 1:

        score += 10

        reasons.append(
            "A failed authentication event occurred."
        )

    elif len(failed_logins) >= 2:

        score += min(
            10 + len(failed_logins) * 5,
            35
        )

        reasons.append(
            f"{len(failed_logins)} failed authentication "
            "events occurred close together."
        )

    # -----------------------------------------------------
    # Suspicious process
    # -----------------------------------------------------

    if suspicious_processes:

        score += 15

        names = sorted({
            event["name"]
            for event in suspicious_processes
        })

        reasons.append(
            "Suspicious process behavior involved: "
            + ", ".join(names)
        )

    # -----------------------------------------------------
    # Suspicious file
    # -----------------------------------------------------

    if suspicious_files:

        score += 10

        names = sorted({
            event["name"]
            for event in suspicious_files
        })

        reasons.append(
            "Suspicious file activity involved: "
            + ", ".join(names[:5])
        )

    # -----------------------------------------------------
    # Suspicious network process
    # -----------------------------------------------------

    if suspicious_network:

        score += 10

        names = sorted({
            event["name"]
            for event in suspicious_network
        })

        reasons.append(
            "Network activity was associated with "
            "a process that matched a warning rule: "
            + ", ".join(names[:5])
        )

    # -----------------------------------------------------
    # Multiple monitoring sources
    # -----------------------------------------------------

    if len(sources) >= 2:

        score += 10

        reasons.append(
            "Related activity came from multiple "
            "monitoring sources."
        )

    # -----------------------------------------------------
    # Authentication + suspicious process
    # -----------------------------------------------------

    if (
        failed_logins
        and suspicious_processes
    ):

        score += 15

        reasons.append(
            "Failed authentication and suspicious "
            "process activity occurred close together."
        )

    # -----------------------------------------------------
    # Process + file
    # -----------------------------------------------------

    if (
        suspicious_processes
        and suspicious_files
    ):

        score += 15

        reasons.append(
            "Suspicious process and file activity "
            "occurred close together."
        )

    # -----------------------------------------------------
    # Process + network
    # -----------------------------------------------------

    if (
        suspicious_processes
        and network_events
    ):

        score += 10

        reasons.append(
            "Suspicious process activity was observed "
            "near a network connection."
        )

    # -----------------------------------------------------
    # Authentication + network
    # -----------------------------------------------------

    if (
        failed_logins
        and network_events
    ):

        score += 5

        reasons.append(
            "Network activity occurred near "
            "failed authentication activity."
        )

    # -----------------------------------------------------
    # Strong four-source correlation
    # -----------------------------------------------------

    source_count = len(sources)

    if source_count >= 4:

        score += 20

        reasons.append(
            "Security, process, file, and network "
            "observations were present in the same "
            "incident window."
        )

    # -----------------------------------------------------
    # IMPORTANT:
    # Do NOT treat a normal HTTPS connection as a threat.
    # -----------------------------------------------------

    score = min(
        score,
        100
    )

    # Weak observations are not alerts.
    if score < 30:
        return None

    # -----------------------------------------------------
    # Threat level
    # -----------------------------------------------------

    if score >= 70:

        level = "HIGH"

    elif score >= 40:

        level = "MEDIUM"

    else:

        level = "LOW"

    # -----------------------------------------------------
    # Title
    # -----------------------------------------------------

    if (
        failed_logins
        and suspicious_processes
        and suspicious_files
        and network_events
    ):

        title = (
            "Authentication + Process + "
            "File + Network Correlation"
        )

    elif (
        failed_logins
        and suspicious_processes
        and network_events
    ):

        title = (
            "Authentication + Process + "
            "Network Correlation"
        )

    elif (
        suspicious_processes
        and suspicious_files
        and network_events
    ):

        title = (
            "Process + File + Network Correlation"
        )

    elif (
        failed_logins
        and suspicious_processes
    ):

        title = (
            "Authentication + Process Correlation"
        )

    elif (
        suspicious_processes
        and network_events
    ):

        title = (
            "Process + Network Correlation"
        )

    elif (
        failed_logins
        and network_events
    ):

        title = (
            "Authentication + Network Activity"
        )

    elif suspicious_network:

        title = (
            "Suspicious Process Network Activity"
        )

    elif failed_logins:

        title = (
            "Repeated Authentication Activity"
        )

    elif suspicious_processes:

        title = (
            "Suspicious Process Activity"
        )

    else:

        title = (
            "Suspicious File Activity"
        )

    if not reasons:

        reasons.append(
            "Multiple related security observations "
            "occurred close together."
        )

    explanation = " ".join(
        reasons
    )

    return {

        "score": score,

        "level": level,

        "title": title,

        "explanation": explanation,

        "events": events,
    }


# =========================================================
# FINGERPRINT
# =========================================================

def make_fingerprint(result):

    event_ids = sorted(
        event["source_id"]
        for event in result["events"]
    )

    raw = (
        result["title"]
        + "|"
        + "|".join(event_ids)
    )

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()


# =========================================================
# SAVE ALERT
# =========================================================

def save_alert(result):

    fingerprint = make_fingerprint(
        result
    )

    events = result["events"]

    first_time = events[0]["time"].strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    last_time = events[-1]["time"].strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    created_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn = sqlite3.connect(
        DATABASE
    )

    try:

        existing = conn.execute(
            """
            SELECT id
            FROM correlation_alerts
            WHERE fingerprint = ?
            """,
            (
                fingerprint,
            )
        ).fetchone()

        if existing:

            return False

        conn.execute(
            """
            INSERT INTO correlation_alerts (

                fingerprint,
                alert_level,
                score,
                title,
                explanation,
                event_count,
                first_event_time,
                last_event_time,
                created_at

            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                fingerprint,
                result["level"],
                result["score"],
                result["title"],
                result["explanation"],
                len(events),
                first_time,
                last_time,
                created_at,
            )
        )

        conn.commit()

        return True

    except sqlite3.Error as error:

        print(
            f"[DATABASE WARNING] {error}"
        )

        return False

    finally:

        conn.close()


# =========================================================
# DISPLAY INCIDENT
# =========================================================

def print_incident(result):

    print()
    print("==========================================")
    print("       CYBER ECHO INCIDENT")
    print("==========================================")

    print(
        f"Level : {result['level']}"
    )

    print(
        f"Score : {result['score']}/100"
    )

    print(
        f"Title : {result['title']}"
    )

    print(
        f"Why   : {result['explanation']}"
    )

    print()

    remote_ips = sorted({
        event.get("remote_ip")
        for event in result["events"]
        if event.get("remote_ip")
    })

    if remote_ips:

        print(
            "Remote IP(s): "
            + ", ".join(remote_ips)
        )

    print()

    print(
        "Related events:"
    )

    for number, event in enumerate(
        result["events"],
        start=1
    ):

        print(
            f"{number}. "
            f"{event['time'].strftime('%Y-%m-%d %H:%M:%S')} | "
            f"{event['source']} | "
            f"{event['name']}"
        )

        print(
            f"   {event['details']}"
        )


# =========================================================
# MAIN
# =========================================================

def main():

    print()
    print("==========================================")
    print("      CYBER ECHO CORRELATION ENGINE")
    print("==========================================")
    print()
    print(
        "Security + Process + File + Network"
    )
    print(
        f"Incident window: "
        f"{INCIDENT_WINDOW_MINUTES} minutes"
    )
    print(
        "Normal network connections are observations."
    )
    print(
        "CYBER ECHO database files are ignored."
    )
    print()

    init_db()

    events = build_events()

    print(
        f"Events analyzed      : {len(events)}"
    )

    if not events:

        print(
            "No events available."
        )

        return

    triggers = build_triggers(
        events
    )

    print(
        f"Meaningful triggers  : {len(triggers)}"
    )

    incidents = []

    fingerprints = set()

    for trigger in triggers:

        related_events = build_incident(
            trigger,
            events
        )

        result = analyze_incident(
            related_events
        )

        if result is None:
            continue

        fingerprint = make_fingerprint(
            result
        )

        if fingerprint in fingerprints:
            continue

        fingerprints.add(
            fingerprint
        )

        incidents.append(
            result
        )

    print(
        f"Incidents detected   : {len(incidents)}"
    )

    saved = 0

    for incident in incidents:

        print_incident(
            incident
        )

        if save_alert(
            incident
        ):

            saved += 1

    print()
    print(
        f"New incidents saved  : {saved}"
    )

    print(
        "CYBER ECHO correlation analysis complete."
    )

    print()


# =========================================================
# START
# =========================================================

if __name__ == "__main__":
    main()
