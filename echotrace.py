
"""EchoTrace: read-only incident timeline for CYBER ECHO."""

from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
import os
import sqlite3

from flask import Blueprint, abort, render_template_string, url_for

echotrace_bp = Blueprint("echotrace", __name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.environ.get(
    "CYBER_ECHO_DATABASE",
    os.path.join(BASE_DIR, "cyber_echo.db")
)

PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EchoTrace | CYBER ECHO</title>
<style>
body {
    margin: 0;
    background: #0b1220;
    color: #e8eefc;
    font: 15px Arial, sans-serif;
}
main { max-width: 1100px; margin: auto; padding: 25px 18px; }
h1 { color: #42d9ff; }
.panel {
    background: #131e31;
    border: 1px solid #263650;
    border-radius: 12px;
    padding: 18px;
    margin: 18px 0;
    overflow-x: auto;
}
a { color: #42d9ff; text-decoration: none; }
a:hover { text-decoration: underline; }
.muted { color: #a9b7ce; }
.warning {
    background: #2b261b;
    border-left: 4px solid #f6bd4b;
    padding: 12px;
}
.pill {
    display: inline-block;
    background: #24354e;
    padding: 5px 9px;
    border-radius: 20px;
}
table { width: 100%; border-collapse: collapse; }
th, td {
    text-align: left;
    padding: 10px;
    border-bottom: 1px solid #293851;
    vertical-align: top;
}
.timeline {
    border-left: 2px solid #42d9ff;
    margin: 20px 0 0 8px;
    padding-left: 20px;
}
.event { position: relative; margin-bottom: 24px; }
.event:before {
    content: "";
    position: absolute;
    left: -27px;
    top: 4px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #42d9ff;
}
.time { color: #9bb0cb; font-size: 13px; }
.kind { font-weight: bold; margin: 5px 0; }
.detail { color: #c4d0e3; overflow-wrap: anywhere; }
button, .btn {
    background: #24354e;
    color: #42d9ff;
    padding: 8px 12px;
    border: 1px solid #38506f;
    border-radius: 7px;
}
</style>
</head>
<body>
<main>
<h1>🧭 EchoTrace</h1>
<p class="muted">Incident investigation and security-event timeline</p>

<div class="panel">
    <a class="btn" href="/">← Back to CYBER ECHO dashboard</a>
    <p class="warning">
        EchoTrace displays recorded evidence. The earliest event shown is
        not necessarily the attack's actual starting point.
    </p>

    {% if error %}
        <p class="warning">{{ error }}</p>
    {% endif %}

    {% if alerts %}
    <h2>Recent correlation alerts</h2>
    <table>
    <thead>
    <tr>
        <th>Level</th>
        <th>Score</th>
        <th>Incident</th>
        <th>First recorded</th>
        <th>Last recorded</th>
        <th>Timeline</th>
    </tr>
    </thead>
    <tbody>
    {% for alert in alerts %}
    <tr>
        <td><span class="pill">{{ alert.level }}</span></td>
        <td>{{ alert.score }}/100</td>
        <td>{{ alert.title }}</td>
        <td>{{ alert.first }}</td>
        <td>{{ alert.last }}</td>
        <td>
            <a href="{{ url_for(
                'echotrace.incident_timeline',
                alert_id=alert.id
            ) }}">Trace →</a>
        </td>
    </tr>
    {% endfor %}
    </tbody>
    </table>
    {% else %}
        <p>No correlation alerts were found.</p>
        <p class="muted">
            Confirm that your existing monitoring and correlation engine
            are running and that they use the same database.
        </p>
    {% endif %}
</div>

{% if selected %}
<div class="panel">
    <h2>{{ selected.title }}</h2>
    <p>
        <span class="pill">{{ selected.level }}</span>
        <span class="pill">Risk {{ selected.score }}/100</span>
    </p>
    <p>{{ selected.explanation }}</p>
    <p class="muted">
        Timeline window: {{ start }} to {{ end }}.
        These events are evidence, not proof of causation.
    </p>

    {% if events %}
    <div class="timeline">
        {% for event in events %}
        <article class="event">
            <div class="time">{{ event.time }}</div>
            <div class="kind">{{ event.source }} · {{ event.kind }}</div>
            <div class="detail">{{ event.description }}</div>
            {% if event.extra %}
                <p class="muted">{{ event.extra }}</p>
            {% endif %}
        </article>
        {% endfor %}
    </div>
    {% else %}
        <p>No matching source events were found in this time window.</p>
    {% endif %}
</div>
{% endif %}

<p class="muted">
Read-only feature. This page does not terminate processes, change
firewall rules, delete files, or quarantine anything.
</p>
</main>
</body>
</html>
"""


def connect_db():
    # mode=ro opens the database read-only at the SQLite level, so EchoTrace
    # cannot change incident records even by accident. It also never creates
    # an empty database file at a wrong path.
    uri = Path(DATABASE).resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


def get_columns(connection, table):
    try:
        return {
            row["name"]
            for row in connection.execute(
                f'PRAGMA table_info("{table}")'
            )
        }
    except sqlite3.Error:
        return set()


def value(row, *names, default=""):
    for name in names:
        if name in row.keys():
            result = row[name]
            if result is not None and str(result).strip():
                return str(result)
    return default


def parse_time(raw):
    if not raw:
        return None

    raw = str(raw).strip()

    formats = (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    )

    for fmt in formats:
        try:
            return datetime.strptime(raw[:26], fmt)
        except ValueError:
            pass

    return None


def load_alert(connection, alert_id):
    columns = get_columns(connection, "correlation_alerts")

    if not columns or "id" not in columns:
        return None

    row = connection.execute(
        "SELECT * FROM correlation_alerts WHERE id = ?",
        (alert_id,)
    ).fetchone()

    if row is None:
        return None

    return {
        "id": int(row["id"]),
        "level": value(row, "alert_level", "level", default="UNKNOWN"),
        "score": value(row, "score", default="0"),
        "title": value(
            row, "title", default="Correlated security activity"
        ),
        "explanation": value(
            row, "explanation", default="No explanation was recorded."
        ),
        "first": value(row, "first_event_time"),
        "last": value(row, "last_event_time"),
    }


def read_events(connection, start, end):
    tables = {
        "Security": (
            "security_events",
            ("event_type", "description", "event_id", "user_name",
             "username", "source_ip", "risk")
        ),
        "Process": (
            "process_events",
            ("process_name", "username", "user_name", "pid",
             "executable_path", "status")
        ),
        "File": (
            "file_events",
            ("event_type", "file_name", "file_path", "risk", "reason")
        ),
        "Network": (
            "network_events",
            ("process_name", "username", "user_name", "remote_ip",
             "remote_port", "protocol", "status")
        ),
    }

    events = []

    for source, (table, _) in tables.items():
        columns = get_columns(connection, table)

        if not columns or "created_at" not in columns:
            continue

        try:
            rows = connection.execute(
                f'SELECT * FROM "{table}" '
                "WHERE created_at >= ? AND created_at <= ? "
                "ORDER BY created_at ASC LIMIT 500",
                (start, end)
            ).fetchall()
        except sqlite3.Error:
            continue

        for row in rows:
            if source == "Security":
                kind = value(
                    row, "event_type", default="Security event"
                )
                description = value(
                    row, "description", default=kind
                )
                details = [
                    "Event ID: " + value(row, "event_id", default="unknown"),
                    "User: " + value(
                        row, "user_name", "username", default="unknown"
                    ),
                    "Source IP: " + value(
                        row, "source_ip", default="unknown"
                    ),
                    "Risk: " + value(row, "risk", default="unknown"),
                ]

            elif source == "Process":
                kind = "Process activity"
                description = value(
                    row, "process_name", default="Unknown process"
                )
                details = [
                    "PID: " + value(row, "pid", default="unknown"),
                    "User: " + value(
                        row, "username", "user_name", default="unknown"
                    ),
                    "Path: " + value(
                        row, "executable_path", default="unknown"
                    ),
                    "Status: " + value(row, "status", default="unknown"),
                ]

            elif source == "File":
                kind = value(row, "event_type", default="File activity")
                description = value(
                    row, "reason",
                    default=value(row, "file_name", default="File change")
                )
                details = [
                    "File: " + value(row, "file_path", default="unknown"),
                    "Risk: " + value(row, "risk", default="unknown"),
                ]

            else:
                kind = "Network activity"
                description = (
                    value(row, "process_name", default="Unknown process")
                    + " connection"
                )
                details = [
                    "Remote: "
                    + value(row, "remote_ip", default="unknown")
                    + ":"
                    + value(row, "remote_port", default="?"),
                    "Protocol: " + value(
                        row, "protocol", default="unknown"
                    ),
                    "Status: " + value(row, "status", default="unknown"),
                ]

            raw_time = value(row, "created_at")

            events.append({
                "source": source,
                "kind": kind,
                "description": description,
                "time": raw_time,
                "sort": parse_time(raw_time) or datetime.min,
                "extra": " · ".join(details),
            })

    events.sort(key=lambda event: event["sort"])
    return events


@echotrace_bp.route("/echotrace")
def index():
    try:
        with closing(connect_db()) as connection:
            columns = get_columns(connection, "correlation_alerts")

            if not columns:
                return render_template_string(
                    PAGE,
                    alerts=[],
                    selected=None,
                    events=[],
                    error=(
                        "The correlation_alerts table does not exist. "
                        "Check that the existing correlation engine has "
                        "created it and uses the same database."
                    ),
                )

            rows = connection.execute(
                "SELECT * FROM correlation_alerts "
                "ORDER BY id DESC LIMIT 50"
            ).fetchall()

            alerts = [{
                "id": int(row["id"]),
                "level": value(
                    row, "alert_level", "level", default="UNKNOWN"
                ),
                "score": value(row, "score", default="0"),
                "title": value(
                    row, "title", default="Correlated security activity"
                ),
                "first": value(
                    row, "first_event_time", default="unknown"
                ),
                "last": value(
                    row, "last_event_time", default="unknown"
                ),
            } for row in rows]

        return render_template_string(
            PAGE,
            alerts=alerts,
            selected=None,
            events=[],
            error="",
        )

    except (sqlite3.Error, OSError) as exc:
        return render_template_string(
            PAGE,
            alerts=[],
            selected=None,
            events=[],
            error=f"Could not read the database: {exc}",
        ), 500


@echotrace_bp.route("/echotrace/<int:alert_id>")
def incident_timeline(alert_id):
    try:
        with closing(connect_db()) as connection:
            selected = load_alert(connection, alert_id)

            if selected is None:
                abort(404)

            first = parse_time(selected["first"])
            last = parse_time(selected["last"])

            if first is None and last is None:
                return render_template_string(
                    PAGE,
                    alerts=[],
                    selected=selected,
                    events=[],
                    error="This alert has no readable timestamps.",
                    start="unknown",
                    end="unknown",
                )

            first = first or last
            last = last or first

            start_dt = first - timedelta(minutes=10)
            end_dt = last + timedelta(minutes=10)

            start = start_dt.strftime("%Y-%m-%d %H:%M:%S")
            end = end_dt.strftime("%Y-%m-%d %H:%M:%S")

            events = read_events(connection, start, end)

            for event in events:
                event.pop("sort", None)

        return render_template_string(
            PAGE,
            alerts=[],
            selected=selected,
            events=events,
            error="",
            start=start,
            end=end,
        )

    except (sqlite3.Error, OSError) as exc:
        return render_template_string(
            PAGE,
            alerts=[],
            selected=None,
            events=[],
            error=f"Could not read the database: {exc}",
        ), 500