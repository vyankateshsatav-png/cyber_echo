from flask import (
    Flask,
    request,
    redirect,
    url_for,
    abort,
    render_template_string,
    flash,
)

import html
import json
import os
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("CYBER_ECHO_SECRET_KEY") or os.urandom(32)
from echotrace import echotrace_bp
app.register_blueprint(echotrace_bp)

from security_routes import security_bp  # noqa: E402
app.register_blueprint(security_bp)

DATABASE = os.environ.get(
    "CYBER_ECHO_DATABASE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyber_echo.db"),
)


# =========================================================
# SMART SHIELD — THREAT ASSESSMENT AND REVIEW TRACKING
# =========================================================

SMART_SHIELD_ACTIONS = {
    "review": "Review the incident and inspect the EchoTrace timeline.",
    "defender_scan": "Run or verify a Microsoft Defender scan.",
    "investigate_process": "Inspect the process path and publisher.",
    "investigate_network": "Review the remote endpoint and process ownership.",
    "investigate_file": "Inspect the file and check it with Microsoft Defender.",
}


def init_smart_shield():
    """Create the Smart Shield review table if it does not exist."""
    conn = sqlite3.connect(DATABASE)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS smart_shield_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'PENDING',
                recommendation TEXT NOT NULL,
                decision_note TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()
    finally:
        conn.close()


def assess_incident(alert):
    """Recommend an investigation step; never execute a response action."""
    title = str(alert["title"] or "").lower()
    explanation = str(alert["explanation"] or "").lower()
    level = str(alert["alert_level"] or "LOW").upper()

    try:
        score = int(alert["score"] or 0)
    except (TypeError, ValueError):
        score = 0

    evidence = title + " " + explanation

    if score >= 70 or level == "HIGH":
        recommendation = "review"
        reason = (
            "Prioritize reviewing this alert. Check the incident timeline "
            "and validate the evidence before taking action."
        )
    elif "file" in evidence:
        recommendation = "investigate_file"
        reason = (
            "File-related activity was reported. Review its path, origin, "
            "and security scan results."
        )
    elif "network" in evidence or "connection" in evidence:
        recommendation = "investigate_network"
        reason = (
            "Network-related activity was reported. Verify the remote "
            "endpoint and owning process."
        )
    elif "process" in evidence:
        recommendation = "investigate_process"
        reason = (
            "Process-related activity was reported. Verify its executable "
            "path, publisher, and related events."
        )
    else:
        recommendation = "review"
        reason = (
            "Review the recorded evidence before deciding whether "
            "any protective action is necessary."
        )

    return {
        "recommendation": recommendation,
        "reason": reason,
        "score": score,
        "level": level,
    }


def save_smart_shield_review(
    alert_id, status, recommendation, note=""
):
    """Record a human review decision without executing it."""
    now = datetime.now().isoformat(timespec="seconds")
    conn = sqlite3.connect(DATABASE)

    try:
        conn.execute("""
            INSERT INTO smart_shield_reviews (
                alert_id, status, recommendation,
                decision_note, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(alert_id) DO UPDATE SET
                status = excluded.status,
                recommendation = excluded.recommendation,
                decision_note = excluded.decision_note,
                updated_at = excluded.updated_at
        """, (
            alert_id,
            status,
            recommendation,
            note[:1000],
            now,
            now,
        ))
        conn.commit()
    finally:
        conn.close()


def get_smart_shield_reviews():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    try:
        return conn.execute("""
            SELECT *
            FROM smart_shield_reviews
            ORDER BY updated_at DESC
            LIMIT 100
        """).fetchall()
    finally:
        conn.close()


# =========================================================
# SMART SHIELD PAGE
# =========================================================

@app.route("/smart-shield", methods=["GET"])
def smart_shield_page():
    init_smart_shield()

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    try:
        alerts = conn.execute("""
            SELECT id, alert_level, score, title, explanation,
                   first_event_time, last_event_time
            FROM correlation_alerts
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()
    finally:
        conn.close()

    saved_reviews = {
        row["alert_id"]: row
        for row in get_smart_shield_reviews()
    }

    incidents = []

    for alert in alerts:
        assessment = assess_incident(alert)
        review = saved_reviews.get(alert["id"])

        incidents.append({
            "id": alert["id"],
            "title": alert["title"] or "Security incident",
            "level": assessment["level"],
            "score": assessment["score"],
            "reason": assessment["reason"],
            "recommendation": assessment["recommendation"],
            "status": review["status"] if review else "PENDING",
            "note": review["decision_note"] if review else "",
        })

    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Smart Shield | CYBER ECHO</title>
      <style>
        body {
          background: #0b1220;
          color: #e8eefc;
          font: 15px Arial, sans-serif;
          max-width: 1100px;
          margin: auto;
          padding: 24px;
        }
        .card {
          background: #131e31;
          border: 1px solid #2b3b55;
          border-radius: 12px;
          padding: 18px;
          margin: 16px 0;
          overflow-wrap: anywhere;
        }
        .muted { color: #afbed4; }
        a { color: #42d9ff; }
        input, select {
          padding: 9px;
          margin: 6px 0;
          max-width: 100%;
        }
        button {
          background: #24354e;
          color: #42d9ff;
          padding: 10px 14px;
          border: 1px solid #38506f;
          border-radius: 6px;
          cursor: pointer;
        }
        .warning {
          background: #302819;
          padding: 12px;
          border-left: 4px solid #f6bd4b;
        }
        .status { font-weight: bold; }
      </style>
    </head>
    <body>
      <h1>🛡️ Smart Shield</h1>
      <p class="muted">Threat assessment and review tracking</p>
      <p>
        <a href="/">← CYBER ECHO Dashboard</a>
        &nbsp; | &nbsp;
        <a href="/echotrace">Open EchoTrace</a>
      </p>

      <p class="warning">
        Alerts are signals for investigation, not proof of compromise.
        This version records review decisions only. It does not terminate
        processes, block connections, or quarantine files.
      </p>

      {% if not incidents %}
        <div class="card">
          No correlated incidents are available for assessment.
        </div>
      {% endif %}

      {% for item in incidents %}
        <div class="card">
          <h2>{{ item.title }}</h2>

          <p>
            <b>Alert ID:</b> {{ item.id }}<br>
            <b>Level:</b> {{ item.level }}<br>
            <b>Score:</b> {{ item.score }}/100<br>
            <b>Review status:</b>
            <span class="status">{{ item.status }}</span>
          </p>

          <p>{{ item.reason }}</p>

          <p>
            <b>Recommended next step:</b>
            {{ action_names.get(
                item.recommendation, "Review incident"
            ) }}
          </p>

          <p>
            <a href="/echotrace/{{ item.id }}">
              Inspect EchoTrace timeline →
            </a>
          </p>

          {% if item.note %}
            <p><b>Previous review note:</b> {{ item.note }}</p>
          {% endif %}

          <form method="post"
                action="/smart-shield/review/{{ item.id }}">
            <label for="decision-{{ item.id }}">Review decision</label><br>
            <select id="decision-{{ item.id }}"
                    name="decision" required>
              <option value="PENDING">Keep pending</option>
              <option value="APPROVED">Approve recommendation</option>
              <option value="REJECTED">Reject recommendation</option>
              <option value="COMPLETED">Mark investigation completed</option>
            </select><br>

            <label for="note-{{ item.id }}">Review note (optional)</label><br>
            <input id="note-{{ item.id }}"
                   name="note"
                   maxlength="1000"
                   style="width:90%"
                   placeholder="Explain your decision"><br>

            <button type="submit">Save review decision</button>
          </form>
        </div>
      {% endfor %}
    </body>
    </html>
    """, incidents=incidents, action_names=SMART_SHIELD_ACTIONS)


# =========================================================
# SAVE A SMART SHIELD REVIEW
# =========================================================

@app.route(
    "/smart-shield/review/<int:alert_id>",
    methods=["POST"]
)
def smart_shield_review(alert_id):
    init_smart_shield()

    decision = request.form.get(
        "decision", "PENDING"
    ).upper()
    note = request.form.get("note", "").strip()

    allowed_decisions = {
        "PENDING",
        "APPROVED",
        "REJECTED",
        "COMPLETED",
    }

    if decision not in allowed_decisions:
        abort(400, description="Invalid review decision.")

    conn = sqlite3.connect(DATABASE)

    try:
        alert = conn.execute("""
            SELECT id, title, explanation, score, alert_level
            FROM correlation_alerts
            WHERE id = ?
        """, (alert_id,)).fetchone()
    finally:
        conn.close()

    if alert is None:
        abort(404)

    assessment = assess_incident({
        "title": alert[1],
        "explanation": alert[2],
        "score": alert[3],
        "alert_level": alert[4],
    })

    save_smart_shield_review(
        alert_id,
        decision,
        assessment["recommendation"],
        note,
    )

    return redirect(url_for("smart_shield_page"))



# =========================================================
# DATABASE HELPER
# =========================================================

def esc(value):
    """Escape text before it is placed into HTML (prevents markup injection)."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def escape_row(row):
    """Return a dict copy of a database row with text values escaped. Numbers are unchanged."""
    return {
        key: (esc(row[key]) if isinstance(row[key], str) else row[key])
        for key in row.keys()
    }


def count_table(table):
    """Exact number of rows in a table (not capped by LIMIT)."""
    conn = sqlite3.connect(DATABASE)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    except sqlite3.Error as error:
        print(f"[DATABASE WARNING] count {table}: {error}")
        return 0
    finally:
        conn.close()


def query_db(query, params=()):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute(query, params).fetchall()
    except sqlite3.Error as error:
        short_query = " ".join(query.split())[:120]
        print(f"[DATABASE WARNING] {error} | {short_query}")
        rows = []

    conn.close()
    return rows


# =========================================================
# EMAIL STATUS
# =========================================================

def get_email_status():

    required = [
        "CYBER_ECHO_EMAIL_FROM",
        "CYBER_ECHO_EMAIL_TO",
        "CYBER_ECHO_EMAIL_PASSWORD",
        "CYBER_ECHO_SMTP_HOST",
        "CYBER_ECHO_SMTP_PORT",
    ]

    missing = [
        name
        for name in required
        if not os.environ.get(name)
    ]

    if missing:
        return "NOT CONFIGURED", "email-off"

    return "READY", "email-on"


# =========================================================
# LOAD DATA
# =========================================================

def get_security_events():
    return query_db("""
        SELECT *
        FROM security_events
        ORDER BY id DESC
        LIMIT 100
    """)


def get_process_events():
    return query_db("""
        SELECT *
        FROM process_events
        ORDER BY id DESC
        LIMIT 100
    """)


def get_file_events():
    return query_db("""
        SELECT *
        FROM file_events
        ORDER BY id DESC
        LIMIT 100
    """)


def get_network_events():
    return query_db("""
        SELECT *
        FROM network_events
        ORDER BY id DESC
        LIMIT 100
    """)


def get_correlation_alerts():
    return query_db("""
        SELECT *
        FROM correlation_alerts
        ORDER BY id DESC
        LIMIT 20
    """)


# =========================================================
# SECURITY STATUS
# =========================================================

def calculate_status(alerts):

    if not alerts:
        return 0, "LOW"

    scores = []

    for alert in alerts:

        try:
            scores.append(
                int(alert["score"] or 0)
            )
        except (ValueError, TypeError):
            pass

    if not scores:
        return 0, "LOW"

    highest_score = max(scores)

    if highest_score >= 70:
        return highest_score, "HIGH"

    if highest_score >= 40:
        return highest_score, "MEDIUM"

    return highest_score, "LOW"


def get_level_class(level):

    if level == "HIGH":
        return "high"

    if level == "MEDIUM":
        return "medium"

    return "low"


# =========================================================
# RECOMMENDATIONS
# =========================================================

def get_recommendations(alert):

    if not alert:

        return [
            "Continue monitoring the system.",
            "Review unfamiliar Windows logon activity when it appears.",
            "Keep Windows and security software updated.",
            "Keep MFA enabled for important accounts.",
        ]

    title = (
        str(alert["title"] or "")
        .lower()
    )

    try:
        score = int(
            alert["score"] or 0
        )
    except (ValueError, TypeError):
        score = 0

    recommendations = []

    if "authentication" in title:

        recommendations.append(
            "Review the related Windows authentication events."
        )

        recommendations.append(
            "Check whether the affected account activity was expected."
        )

    if "process" in title:

        recommendations.append(
            "Review the process name, PID, executable path, and time."
        )

        recommendations.append(
            "Verify that the process is expected on this computer."
        )

    if "file" in title:

        recommendations.append(
            "Review the files involved in the correlated activity."
        )

        recommendations.append(
            "Check whether the file activity was expected."
        )

    if "network" in title:

        recommendations.append(
            "Review the remote IP, remote port, process, and connection time."
        )

        recommendations.append(
            "Do not assume an IP is malicious solely because it appears in a connection."
        )

    if score >= 70:

        recommendations.append(
            "Investigate the related evidence before treating the signal as a confirmed compromise."
        )

    elif score >= 40:

        recommendations.append(
            "Review the correlated events for unusual behavior."
        )

    if not recommendations:

        recommendations.append(
            "Continue monitoring the related security activity."
        )

    # Remove duplicates
    final = []

    for item in recommendations:

        if item not in final:
            final.append(item)

    return final


# =========================================================
# CORRELATION HTML
# =========================================================

def build_alert_rows(alerts):

    html = ""

    for alert in map(escape_row, alerts):

        level = str(
            alert["alert_level"] or "LOW"
        )

        if level == "HIGH":
            css = "high-text"

        elif level == "MEDIUM":
            css = "medium-text"

        else:
            css = "low-text"

        html += f"""
        <tr>

            <td class="{css}">
                {level}
            </td>

            <td>
                {alert["score"]}/100
            </td>

            <td>
                {alert["title"]}
            </td>

            <td>
                {alert["event_count"]}
            </td>

            <td>
                {alert["first_event_time"]}
            </td>

            <td>
                {alert["last_event_time"]}
            </td>

            <td>
                {alert["explanation"]}
            </td>

        </tr>
        """

    if not html:

        html = """
        <tr>
            <td colspan="7">
                No correlated incidents recorded.
            </td>
        </tr>
        """

    return html


# =========================================================
# SECURITY HTML
# =========================================================

def build_security_rows(events):

    html = ""

    for event in map(escape_row, events):

        event_id = event["event_id"]

        if event_id == 4625:
            icon = "⚠️"

        elif event_id == 4624:
            icon = "✅"

        else:
            icon = "🔍"

        source_ip = (
            event["source_ip"]
            or "Local/Unknown"
        )

        html += f"""
        <tr>

            <td>
                {icon} {event["event_type"]}
            </td>

            <td>
                {event["user_name"]}
            </td>

            <td>
                {source_ip}
            </td>

            <td>
                {event_id}
            </td>

            <td>
                {event["risk"]}
            </td>

            <td>
                {event["created_at"]}
            </td>

        </tr>
        """

    if not html:

        html = """
        <tr>
            <td colspan="6">
                No Windows Security events found.
            </td>
        </tr>
        """

    return html


# =========================================================
# PROCESS HTML
# =========================================================

def build_process_rows(events):

    html = ""

    for event in map(escape_row, events):

        html += f"""
        <tr>

            <td>
                {event["process_name"]}
            </td>

            <td>
                {event["pid"]}
            </td>

            <td>
                {event["username"]}
            </td>

            <td>
                {event["status"]}
            </td>

            <td class="path">
                {event["executable_path"]}
            </td>

            <td>
                {event["created_at"]}
            </td>

        </tr>
        """

    if not html:

        html = """
        <tr>
            <td colspan="6">
                No process events found.
            </td>
        </tr>
        """

    return html


# =========================================================
# FILE HTML
# =========================================================

def build_file_rows(events):

    html = ""

    for event in map(escape_row, events):

        try:
            risk = int(event["risk"] or 0)
        except (ValueError, TypeError):
            risk = 0

        if risk >= 20:
            css = "high-text"

        elif risk > 0:
            css = "medium-text"

        else:
            css = "low-text"

        html += f"""
        <tr>

            <td>
                {event["event_type"]}
            </td>

            <td>
                {event["file_name"]}
            </td>

            <td class="path">
                {event["file_path"]}
            </td>

            <td class="{css}">
                {risk}
            </td>

            <td>
                {event["reason"] or "None"}
            </td>

            <td>
                {event["created_at"]}
            </td>

        </tr>
        """

    if not html:

        html = """
        <tr>
            <td colspan="6">
                No file events found.
            </td>
        </tr>
        """

    return html


# =========================================================
# NETWORK HTML
# =========================================================

def build_network_rows(events):

    html = ""

    for event in map(escape_row, events):

        remote_ip = (
            event["remote_ip"]
            or "Unknown"
        )

        remote_port = (
            event["remote_port"]
            or ""
        )

        protocol = (
            event["protocol"]
            or ""
        )

        status = (
            event["status"]
            or ""
        )

        html += f"""
        <tr>

            <td>
                {event["process_name"] or "Unknown"}
            </td>

            <td>
                {event["pid"]}
            </td>

            <td>
                {event["username"] or "Unknown"}
            </td>

            <td class="remote-ip">
                {remote_ip}
            </td>

            <td>
                {remote_port}
            </td>

            <td>
                {protocol}
            </td>

            <td>
                {status}
            </td>

            <td>
                {event["created_at"]}
            </td>

        </tr>
        """

    if not html:

        html = """
        <tr>
            <td colspan="8">
                No external network connections recorded yet.
            </td>
        </tr>
        """

    return html


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
def dashboard():

    security_events = get_security_events()
    process_events = get_process_events()
    file_events = get_file_events()
    network_events = get_network_events()
    alerts = get_correlation_alerts()
    sec_total = count_table("security_events")
    proc_total = count_table("process_events")
    file_total = count_table("file_events")
    net_total = count_table("network_events")
    alert_total = count_table("correlation_alerts")

    email_status, email_class = (
        get_email_status()
    )

    score, level = calculate_status(
        alerts
    )

    # IMPORTANT:
    # This prevents the old NameError.
    level_class = get_level_class(
        level
    )

    # -----------------------------------------------------
    # Latest alert
    # -----------------------------------------------------

    if alerts:

        latest = alerts[0]

        latest_title = (
            esc(latest["title"])
        )

        latest_explanation = (
            esc(latest["explanation"])
        )

    else:

        latest = None

        latest_title = (
            "No Correlated Incident"
        )

        latest_explanation = (
            "No strong correlated security pattern "
            "is currently recorded."
        )

    # -----------------------------------------------------
    # Recommendation HTML
    # -----------------------------------------------------

    recommendations = get_recommendations(
        latest
    )

    recommendation_html = ""

    for recommendation in map(esc, recommendations):

        recommendation_html += f"""
        <div class="recommendation">
            🛡️ {recommendation}
        </div>
        """

    # -----------------------------------------------------
    # Status box
    # -----------------------------------------------------

    if level == "HIGH":

        status_box = f"""
        <div class="alert">

            <h3>
                🚨 HIGH-RISK SIGNAL
            </h3>

            <p>
                <strong>{latest_title}</strong>
            </p>

            <p>
                {latest_explanation}
            </p>

            <p class="small">
                This is a detection signal, not automatic
                proof that the computer is compromised.
            </p>

        </div>
        """

    elif level == "MEDIUM":

        status_box = f"""
        <div class="medium-box">

            <h3>
                ⚠️ ACTIVITY REQUIRES REVIEW
            </h3>

            <p>
                <strong>{latest_title}</strong>
            </p>

            <p>
                {latest_explanation}
            </p>

            <p class="small">
                Review the related evidence before drawing
                a security conclusion.
            </p>

        </div>
        """

    else:

        status_box = f"""
        <div class="success">

            <h3>
                ✅ NO HIGH-CONFIDENCE THREAT DETECTED
            </h3>

            <p>
                <strong>{latest_title}</strong>
            </p>

            <p>
                {latest_explanation}
            </p>

        </div>
        """

    # -----------------------------------------------------
    # Table HTML
    # -----------------------------------------------------

    alert_rows = build_alert_rows(
        alerts
    )

    security_rows = build_security_rows(
        security_events
    )

    process_rows = build_process_rows(
        process_events
    )

    file_rows = build_file_rows(
        file_events
    )

    network_rows = build_network_rows(
        network_events
    )

    # =====================================================
    # PAGE
    # =====================================================

    return f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<meta
    http-equiv="refresh"
    content="10"
>

<title>CYBER ECHO</title>


<style>

body {{

    margin: 0;

    padding: 0;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background: #0b1220;

    color: white;

}}


.container {{

    width: 94%;

    max-width: 1450px;

    margin: auto;

    padding: 30px 0 60px;

}}


h1 {{

    text-align: center;

    font-size: 48px;

    color: #00c8ff;

    margin: 0 0 5px;

}}


.subtitle {{

    text-align: center;

    color: #b8c2d1;

    margin-bottom: 30px;

}}


.cards {{

    display: flex;

    flex-wrap: wrap;

    gap: 18px;

}}


.card {{

    background: #172033;

    border-radius: 15px;

    padding: 22px;

    flex: 1;

    min-width: 160px;

    text-align: center;

}}


.card h2 {{

    margin-top: 0;

    font-size: 18px;

}}


.score {{

    font-size: 40px;

    font-weight: bold;

}}


.high {{

    color: #ff4d5a;

}}


.medium {{

    color: #ffb347;

}}


.low {{

    color: #00ff88;

}}


.section {{

    background: #172033;

    margin-top: 22px;

    padding: 25px;

    border-radius: 15px;

}}


.info {{

    color: #b8c2d1;

    line-height: 1.6;

}}


.small {{

    color: #9ca9ba;

    font-size: 13px;

}}


.alert {{

    background: #32151a;

    border:
        1px solid
        #ff4d5a;

    border-radius: 12px;

    padding: 20px;

}}


.medium-box {{

    background: #302614;

    border:
        1px solid
        #ffb347;

    border-radius: 12px;

    padding: 20px;

}}


.success {{

    background: #11281e;

    border:
        1px solid
        #00ff88;

    border-radius: 12px;

    padding: 20px;

}}


.recommendation {{

    background: #101a2c;

    border-left:
        4px solid
        #00c8ff;

    padding: 14px;

    margin: 10px 0;

    border-radius: 8px;

}}


.email-on {{

    background: #11281e;

    border:
        1px solid
        #00ff88;

    border-radius: 12px;

    padding: 20px;

}}


.email-off {{

    background: #32151a;

    border:
        1px solid
        #ff4d5a;

    border-radius: 12px;

    padding: 20px;

}}


table {{

    width: 100%;

    border-collapse:
        collapse;

    margin-top: 15px;

}}


th,
td {{

    padding: 11px;

    border-bottom:
        1px solid
        #34405a;

    text-align: left;

    vertical-align: top;

    font-size: 13px;

}}


th {{

    color: #00c8ff;

}}


.high-text {{

    color: #ff4d5a;

    font-weight: bold;

}}


.medium-text {{

    color: #ffb347;

    font-weight: bold;

}}


.low-text {{

    color: #00ff88;

    font-weight: bold;

}}


.path {{

    word-break:
        break-all;

    color: #aeb9ca;

}}


.remote-ip {{

    color: #00c8ff;

    font-weight: bold;

}}


.architecture {{

    text-align: center;

    color: #00c8ff;

    font-size: 19px;

    line-height: 2;

}}


@media (max-width: 800px) {{

    h1 {{
        font-size: 34px;
    }}

    table {{
        display: block;
        overflow-x: auto;
    }}

}}

</style>

</head>


<body>


<div class="container">


<h1>
🛡️ CYBER ECHO
</h1>

<div class="subtitle">
Real-Time Windows Security Monitoring & Automated Protection
</div>

<p class="nav-links"><a href="/security">Owner security &amp; face guard</a> &middot; <a href="/echotrace">EchoTrace timeline</a></p>


<!-- =====================================================
     SUMMARY
====================================================== -->

<div class="cards">


<div class="card">

<h2>
Highest Alert Risk
</h2>

<div class="score {level_class}">
{score}/100
</div>

</div>


<div class="card">

<h2>
Threat Level
</h2>

<div class="score {level_class}">
{level}
</div>

</div>


<div class="card">

<h2>
Windows Events
</h2>

<div class="score">
{sec_total}
</div>

</div>


<div class="card">

<h2>
Process Events
</h2>

<div class="score">
{proc_total}
</div>

</div>


<div class="card">

<h2>
File Events
</h2>

<div class="score">
{file_total}
</div>

</div>


<div class="card">

<h2>
Network Events
</h2>

<div class="score">
{net_total}
</div>

</div>


<div class="card">

<h2>
Correlated Incidents
</h2>

<div class="score">
{alert_total}
</div>

</div>


</div>


<!-- =====================================================
     ASSESSMENT
====================================================== -->

<div class="section">

<h2>
🧠 CYBER ECHO Assessment
</h2>

{status_box}

</div>


<!-- =====================================================
     EMAIL
====================================================== -->

<div class="section">

<h2>
📧 Email Alert Status
</h2>

<div class="{email_class}">

<h3>
📧 Automatic Email Alerts:
{email_status}
</h3>

<p>
CYBER ECHO can automatically send security
notifications when a qualifying incident is detected.
</p>

<p class="small">
Emails can include available source/remote IPs,
device information, username, processes, files,
network activity, risk score, and action taken.
</p>

</div>

</div>


<!-- =====================================================
     RECOMMENDATIONS
====================================================== -->

<div class="section">

<h2>
🛡️ Recommended Investigation
</h2>

<p class="info">
Recommendations are based on the current detection signals.
</p>

{recommendation_html}

</div>


<!-- =====================================================
     CORRELATED INCIDENTS
====================================================== -->

<div class="section">

<h2>
🔗 Correlated Security Incidents
</h2>

<p class="info">
CYBER ECHO combines related activity from Windows Security,
process, file, and network monitoring.
</p>

<table>

<tr>

<th>Level</th>
<th>Score</th>
<th>Incident</th>
<th>Events</th>
<th>First Event</th>
<th>Last Event</th>
<th>Explanation</th>

</tr>

{alert_rows}

</table>

</div>


<!-- =====================================================
     WINDOWS SECURITY
====================================================== -->

<div class="section">

<h2>
🔐 Windows Security Events
</h2>

<table>

<tr>

<th>Event</th>
<th>User</th>
<th>Source IP</th>
<th>ID</th>
<th>Risk</th>
<th>Time</th>

</tr>

{security_rows}

</table>

</div>


<!-- =====================================================
     PROCESSES
====================================================== -->

<div class="section">

<h2>
⚙️ Real Process Activity
</h2>

<table>

<tr>

<th>Process</th>
<th>PID</th>
<th>User</th>
<th>Status</th>
<th>Executable</th>
<th>Recorded</th>

</tr>

{process_rows}

</table>

</div>


<!-- =====================================================
     FILES
====================================================== -->

<div class="section">

<h2>
📂 Real File Activity
</h2>

<table>

<tr>

<th>Action</th>
<th>File</th>
<th>Path</th>
<th>Risk</th>
<th>Reason</th>
<th>Time</th>

</tr>

{file_rows}

</table>

</div>


<!-- =====================================================
     NETWORK
====================================================== -->

<div class="section">

<h2>
🌐 Real Network Activity
</h2>

<p class="info">
CYBER ECHO records external network connections and
associates them with the process when available.
</p>

<table>

<tr>

<th>Process</th>
<th>PID</th>
<th>User</th>
<th>Remote IP</th>
<th>Remote Port</th>
<th>Protocol</th>
<th>Status</th>
<th>Time</th>

</tr>

{network_rows}

</table>

</div>


<!-- =====================================================
     ARCHITECTURE
====================================================== -->

<div class="section">

<h2>
🧩 CYBER ECHO Architecture
</h2>

<div class="architecture">

Windows Security
<br>
↓
<br>
Process Monitoring
<br>
↓
<br>
File Monitoring
<br>
↓
<br>
Network + Remote IP Monitoring
<br>
↓
<br>
Correlation Engine
<br>
↓
<br>
Risk Analysis
<br>
↓
<br>
Automatic Email Alert
<br>
↓
<br>
Defender Protection for Qualifying Incidents

</div>

</div>


<!-- =====================================================
     SYSTEM STATUS
====================================================== -->

<div class="section">

<h2>
🟢 System Status
</h2>

<p class="low-text">
✅ Windows Security data connected
</p>

<p class="low-text">
✅ Process monitoring data connected
</p>

<p class="low-text">
✅ File monitoring data connected
</p>

<p class="low-text">
✅ Network monitoring data connected
</p>

<p class="low-text">
✅ Correlation data connected
</p>

<p class="low-text">
📧 Email configuration: {email_status}
</p>

<p class="info">
🔄 Dashboard automatically refreshes every 10 seconds.
</p>

<p class="small">
Database:
{os.path.abspath(DATABASE)}
</p>

</div>


</div>

</body>

</html>
"""


# =========================================================
# START
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=False,
        use_reloader=False,
        host="127.0.0.1",
        port=5000
        
    )