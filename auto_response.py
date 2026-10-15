import ipaddress
import os
import smtplib
import socket
import sqlite3
import subprocess
import time
from datetime import datetime, timedelta
from email.message import EmailMessage


DATABASE = os.environ.get(
    "CYBER_ECHO_DATABASE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyber_echo.db"),
)

CHECK_INTERVAL = 10
EMAIL_RETRY_SECONDS = 60
DEFENDER_COOLDOWN_MINUTES = 30

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Automatic Defender scans are opt-in. Set CYBER_ECHO_AUTO_DEFENDER_SCAN=1 to allow them.
DEFENDER_AUTO_SCAN_ENABLED = os.environ.get("CYBER_ECHO_AUTO_DEFENDER_SCAN", "0") == "1"
NOTIFY_FAILURE_LOG = os.path.join(BASE_DIR, "notify_failures.log")
LAST_ALERT_FILE = os.path.join(BASE_DIR, "auto_response_last_alert.txt")
DEFENDER_STATE_FILE = os.path.join(BASE_DIR, "auto_response_defender_time.txt")


# =========================================================
# EMAIL CONFIGURATION
# =========================================================

def get_email_settings():
    try:
        port = int(
            os.environ.get(
                "CYBER_ECHO_SMTP_PORT", "587"
            )
        )
    except ValueError:
        port = 587

    return {
        "sender": os.environ.get(
            "CYBER_ECHO_EMAIL_FROM", ""
        ),
        "recipient": os.environ.get(
            "CYBER_ECHO_EMAIL_TO", ""
        ),
        "password": os.environ.get(
            "CYBER_ECHO_EMAIL_PASSWORD", ""
        ),
        "smtp_host": os.environ.get(
            "CYBER_ECHO_SMTP_HOST", ""
        ),
        "smtp_port": port,
    }


# =========================================================
# DATABASE HELPERS
# =========================================================

def get_new_alerts(last_alert_id):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    try:
        alerts = conn.execute("""
            SELECT *
            FROM correlation_alerts
            WHERE id > ?
            ORDER BY id ASC
        """, (last_alert_id,)).fetchall()
    except sqlite3.Error as error:
        print(f"[DATABASE ERROR] {error}")
        alerts = []

    conn.close()
    return alerts


def get_events_for_alert(table, alert):
    # Table names are restricted to this internal allowlist.
    allowed_tables = {
        "security_events",
        "process_events",
        "file_events",
        "network_events",
    }

    if table not in allowed_tables:
        raise ValueError("Unsupported database table")

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute(
            f"""
            SELECT *
            FROM {table}
            WHERE created_at >= ?
              AND created_at <= ?
            ORDER BY created_at ASC
            """,
            (
                alert["first_event_time"],
                alert["last_event_time"],
            ),
        ).fetchall()
    except sqlite3.Error as error:
        print(f"[DATABASE WARNING] {table}: {error}")
        rows = []

    conn.close()
    return rows


# =========================================================
# IP HELPERS
# =========================================================

def clean_ip(value):
    if not value:
        return None

    value = str(value).strip()

    if value.lower() in {
        "", "-", "unknown", "local/unknown", "localhost"
    }:
        return None

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None

    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
    ):
        return None

    # Private remote addresses are retained. They can still
    # identify another device on a home or office network.
    return str(address)


def get_security_source_ips(events):
    ips = []

    for event in events:
        ip = clean_ip(event["source_ip"])

        if ip and ip not in ips:
            ips.append(ip)

    return ips


def get_network_remote_ips(events):
    ips = []

    for event in events:
        ip = clean_ip(event["remote_ip"])

        if ip and ip not in ips:
            ips.append(ip)

    return ips


# =========================================================
# DEVICE INFORMATION
# =========================================================

def get_device_name():
    try:
        return socket.gethostname()
    except Exception:
        return "Unknown"


def get_local_ips():
    addresses = []

    try:
        results = socket.getaddrinfo(
            socket.gethostname(), None
        )

        for result in results:
            address = result[4][0]

            if address not in addresses:
                addresses.append(address)

    except Exception:
        pass

    return addresses


# =========================================================
# ALERT SEVERITY
# =========================================================

def get_alert_level(alert):
    level = str(
        alert["alert_level"] or "LOW"
    ).upper()

    try:
        score = int(alert["score"] or 0)
    except (ValueError, TypeError):
        score = 0

    # Use both the stored level and score, so MEDIUM/HIGH
    # alerts aren't accidentally suppressed by a mismatch.
    if level == "HIGH" or score >= 70:
        return "HIGH"

    if level == "MEDIUM" or score >= 40:
        return "MEDIUM"

    return "LOW"


def should_email(alert):
    return get_alert_level(alert) in {
        "MEDIUM",
        "HIGH",
    }


# =========================================================
# MICROSOFT DEFENDER
# =========================================================

def defender_scan_allowed():
    if not os.path.exists(DEFENDER_STATE_FILE):
        return True

    try:
        with open(
            DEFENDER_STATE_FILE, "r", encoding="utf-8"
        ) as file:
            previous = datetime.fromisoformat(
                file.read().strip()
            )

        return (
            datetime.now() - previous
            >= timedelta(
                minutes=DEFENDER_COOLDOWN_MINUTES
            )
        )
    except Exception:
        return True


def record_defender_scan_time():
    with open(
        DEFENDER_STATE_FILE, "w", encoding="utf-8"
    ) as file:
        file.write(datetime.now().isoformat())


def start_defender_scan():
    if not defender_scan_allowed():
        return (
            False,
            "Scan not started: the 30-minute cooldown is active.",
        )

    command = (
        "$ErrorActionPreference='Stop'; "
        "Start-MpScan -ScanType QuickScan "
        "-ErrorAction Stop; "
        "Write-Output 'DEFENDER_SCAN_COMMAND_SUCCEEDED'"
    )

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        if (
            result.returncode == 0
            and "DEFENDER_SCAN_COMMAND_SUCCEEDED"
            in result.stdout
        ):
            record_defender_scan_time()
            return (
                True,
                "Microsoft Defender accepted the Quick Scan command.",
            )

        detail = (
            result.stderr.strip()
            or result.stdout.strip()
            or "PowerShell did not confirm success."
        )

        return (
            False,
            f"Defender scan was not confirmed: {detail}",
        )

    except Exception as error:
        return (
            False,
            f"Defender scan error: {error}",
        )


def should_start_defender(alert, security_events):
    level = get_alert_level(alert)
    title = str(alert["title"] or "").lower()

    failed_logon_found = any(
        event["event_id"] == 4625
        for event in security_events
    )

    has_independent_activity = any(
        word in title
        for word in ("process", "file", "network")
    )

    # This is a conservative rule, not proof an attack occurred.
    return (
        level == "HIGH"
        and failed_logon_found
        and has_independent_activity
    )


# =========================================================
# EMAIL DETAILS
# =========================================================

def security_details(events):
    if not events:
        return "No matching Windows Security events were found."

    lines = []

    for event in events:
        keys = set(event.keys())

        def value(name):
            return (
                event[name]
                if name in keys and event[name] is not None
                else "Unknown"
            )

        lines.extend([
            f"Time: {value('created_at')}",
            f"Event ID: {value('event_id')}",
            f"Event: {value('event_type')}",
            f"Username: {value('user_name')}",
            f"Source IP: {value('source_ip')}",
            f"Source port: {value('source_port')}",
            f"Workstation: {value('workstation_name')}",
            f"Logon type: {value('logon_type')}",
            f"Authentication package: {value('authentication_package')}",
            "",
        ])

    return "\n".join(lines)


def process_details(events):
    if not events:
        return "No matching process events were found."

    lines = []

    for event in events:
        lines.extend([
            f"Time: {event['created_at']}",
            f"Process: {event['process_name']}",
            f"PID: {event['pid']}",
            f"User: {event['username']}",
            f"Status: {event['status']}",
            f"Executable: {event['executable_path']}",
            "",
        ])

    return "\n".join(lines)


def file_details(events):
    if not events:
        return "No matching file events were found."

    lines = []

    for event in events:
        lines.extend([
            f"Time: {event['created_at']}",
            f"Action: {event['event_type']}",
            f"File: {event['file_name']}",
            f"Risk: {event['risk']}",
            f"Path: {event['file_path']}",
            f"Reason: {event['reason'] or 'None'}",
            "",
        ])

    return "\n".join(lines)


def network_details(events):
    if not events:
        return "No matching network events were found."

    lines = []

    for event in events:
        lines.extend([
            f"Time: {event['created_at']}",
            f"Process: {event['process_name']}",
            f"PID: {event['pid']}",
            f"User: {event['username']}",
            f"Protocol: {event['protocol']}",
            f"Local address: {event['local_ip']}:{event['local_port']}",
            f"Remote IP: {event['remote_ip']}",
            f"Remote port: {event['remote_port']}",
            f"Status: {event['status']}",
            f"Executable: {event['executable_path']}",
            "",
        ])

    return "\n".join(lines)


# =========================================================
# SEND EMAIL
# =========================================================

def send_email(
    alert,
    security_events,
    process_events,
    file_events,
    network_events,
    protection_action,
):
    settings = get_email_settings()

    required = [
        settings["sender"],
        settings["recipient"],
        settings["password"],
        settings["smtp_host"],
    ]

    if not all(required):
        print("[EMAIL ERROR] Email settings are not configured.")
        return False

    security_ips = get_security_source_ips(
        security_events
    )

    network_ips = get_network_remote_ips(
        network_events
    )

    all_ips = []

    for ip in security_ips + network_ips:
        if ip not in all_ips:
            all_ips.append(ip)

    remote_ip_text = (
        "\n".join(f"- {ip}" for ip in all_ips)
        if all_ips
        else "No remote/source IP was available in the matching events."
    )

    local_ip_text = (
        "\n".join(f"- {ip}" for ip in get_local_ips())
        or "Unavailable"
    )

    severity = get_alert_level(alert)

    message = EmailMessage()
    message["From"] = settings["sender"]
    message["To"] = settings["recipient"]
    message["Subject"] = (
        f"CYBER ECHO ALERT | {severity} | "
        f"{alert['score']}/100"
    )

    message.set_content(f"""
CYBER ECHO SECURITY ALERT
=========================

Severity: {severity}
Risk score: {alert['score']}/100
Incident: {alert['title']}

Explanation:
{alert['explanation']}

DEVICE
======

Computer name: {get_device_name()}

Local IP address(es):
{local_ip_text}

SOURCE / REMOTE IP
==================

{remote_ip_text}

TIME
====

First event: {alert['first_event_time']}
Last event: {alert['last_event_time']}
Email generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

PROTECTION ACTION
=================

{protection_action}

WINDOWS SECURITY EVENTS
=======================

{security_details(security_events)}

PROCESS ACTIVITY
================

{process_details(process_events)}

FILE ACTIVITY
=============

{file_details(file_events)}

NETWORK ACTIVITY
================

{network_details(network_events)}

IMPORTANT
=========

An IP appearing in a connection does not by itself prove
that the IP is malicious. A detection score is a rule-based
signal, not confirmation that the computer is compromised.
""")

    try:
        with smtplib.SMTP(
            settings["smtp_host"],
            settings["smtp_port"],
            timeout=30,
        ) as smtp:
            smtp.starttls()
            smtp.login(
                settings["sender"],
                settings["password"],
            )
            smtp.send_message(message)

        print("[EMAIL] Detailed alert sent successfully.")
        return True

    except Exception as error:
        print(f"[EMAIL ERROR] {error}")
        return False


# =========================================================
# PROCESS ALERT
# =========================================================

def process_alert(alert):
    level = get_alert_level(alert)

    print()
    print("==========================================")
    print("       CYBER ECHO AUTO RESPONSE")
    print("==========================================")
    print(f"Alert ID : {alert['id']}")
    print(f"Level    : {level}")
    print(f"Score    : {alert['score']}/100")
    print(f"Incident : {alert['title']}")

    security_events = get_events_for_alert(
        "security_events", alert
    )
    process_events = get_events_for_alert(
        "process_events", alert
    )
    file_events = get_events_for_alert(
        "file_events", alert
    )
    network_events = get_events_for_alert(
        "network_events", alert
    )

    # Only HIGH alerts that meet the extra evidence rule
    # may trigger a Defender Quick Scan.
    if not DEFENDER_AUTO_SCAN_ENABLED:
        protection_action = (
            "Automatic Defender scan is disabled. "
            "Set CYBER_ECHO_AUTO_DEFENDER_SCAN=1 to enable it."
        )
    elif should_start_defender(alert, security_events):
        _, protection_action = start_defender_scan()
    else:
        protection_action = (
            "No automatic Defender scan started: the "
            "high-severity and corroborating-evidence "
            "requirements were not met."
        )

    print(f"[PROTECTION] {protection_action}")

    # LOW events are handled without sending email.
    if not should_email(alert):
        print("[EMAIL] LOW-risk alert recorded; email skipped.")
        return True

    # MEDIUM and HIGH alerts are emailed. A missing or failing email must not
    # block later alerts, so the alert is marked handled after a few attempts.
    if not email_settings_ready():
        print("[EMAIL] Not configured. Alert recorded but not emailed.")
        log_notify_failure(alert, "email not configured")
        return True

    for attempt in range(1, 4):
        if send_email(
            alert,
            security_events,
            process_events,
            file_events,
            network_events,
            protection_action,
        ):
            return True
        print(f"[EMAIL] Attempt {attempt} of 3 failed.")
        time.sleep(5)

    log_notify_failure(alert, "SMTP send failed after 3 attempts")
    return True


# =========================================================
# LAST ALERT STATE
# =========================================================

def load_last_alert_id():
    if not os.path.exists(LAST_ALERT_FILE):
        return 0

    try:
        with open(
            LAST_ALERT_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            return int(file.read().strip())
    except Exception:
        return 0


def save_last_alert_id(alert_id):
    with open(
        LAST_ALERT_FILE,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(str(alert_id))


# =========================================================
# MAIN SERVICE
# =========================================================

def email_settings_ready():
    settings = get_email_settings()
    return all([
        settings["sender"],
        settings["recipient"],
        settings["password"],
        settings["smtp_host"],
    ])


def log_notify_failure(alert, reason):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(NOTIFY_FAILURE_LOG, "a", encoding="utf-8") as file:
            file.write(f"{stamp} alert {alert['id']} not emailed: {reason}\n")
    except OSError:
        pass


def get_latest_alert_id():
    try:
        conn = sqlite3.connect(DATABASE)
        try:
            row = conn.execute(
                "SELECT COALESCE(MAX(id), 0) FROM correlation_alerts"
            ).fetchone()
            return int(row[0] or 0)
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


def main():
    print()
    print("==========================================")
    print("       CYBER ECHO AUTO RESPONSE")
    print("==========================================")
    print()
    print("Automatic incident processing: ACTIVE")
    print("Medium/high email alerts: ENABLED")
    print("Source/remote IP reporting: ENABLED")
    print(
        "Defender Quick Scan: ENABLED (opt-in)"
        if DEFENDER_AUTO_SCAN_ENABLED
        else "Defender Quick Scan: disabled (set CYBER_ECHO_AUTO_DEFENDER_SCAN=1 to enable)"
    )
    print("Press CTRL+C to stop.")
    print()

    if not os.path.exists(LAST_ALERT_FILE):
        existing = get_latest_alert_id()
        save_last_alert_id(existing)
        print(f"First run: {existing} existing alert(s) skipped. "
              "Only new alerts will be emailed.")

    last_alert_id = load_last_alert_id()
    retry_at = 0.0

    while True:
        try:
            if time.monotonic() < retry_at:
                time.sleep(1)
                continue

            alerts = get_new_alerts(last_alert_id)

            if not alerts:
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] "
                    "No new correlation alerts."
                )
                time.sleep(CHECK_INTERVAL)
                continue

            for alert in alerts:
                processed = process_alert(alert)

                if not processed:
                    print(
                        "[RETRY] Email delivery failed. "
                        f"Will retry in {EMAIL_RETRY_SECONDS} seconds."
                    )
                    retry_at = (
                        time.monotonic()
                        + EMAIL_RETRY_SECONDS
                    )
                    break

                last_alert_id = int(alert["id"])
                save_last_alert_id(last_alert_id)

            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print()
            print("CYBER ECHO auto-response stopped.")
            break

        except Exception as error:
            print(f"[AUTO RESPONSE ERROR] {error}")
            time.sleep(CHECK_INTERVAL)


# =========================================================
# START
# =========================================================

if __name__ == "__main__":
    main()