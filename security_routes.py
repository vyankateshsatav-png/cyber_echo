"""Owner security pages.

/security                admin page, reachable only from this device
/security/respond/...    approval page linked from the owner's email (secret token + passphrase)
"""

import os
from datetime import datetime, timedelta

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template_string,
    request,
    send_file,
    url_for,
)

import face_guard
import notifier
import security_store as store
import vault

security_bp = Blueprint("security", __name__)

LOCAL_ADDRESSES = {"127.0.0.1", "::1"}
PUBLIC_ENDPOINTS = {"security.respond", "security.respond_snapshot"}

CSS = """
:root { --bg:#0b1220; --panel:#131e31; --line:#263650; --text:#e8eefc;
        --muted:#a9b7ce; --cyan:#42d9ff; --green:#41e0a0; --red:#ff6b7a; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px Arial, sans-serif; }
main { max-width:1100px; margin:auto; padding:24px 18px; }
h1 { color:var(--cyan); margin:0 0 6px; }
h2 { color:var(--cyan); font-size:18px; margin:4px 0 12px; }
a { color:var(--cyan); }
.panel { background:var(--panel); border:1px solid var(--line); border-radius:12px;
         padding:18px; margin:16px 0; overflow-x:auto; }
.muted { color:var(--muted); font-size:13px; }
.flash { padding:10px 14px; border-radius:8px; margin:12px 0;
         border-left:4px solid var(--cyan); background:#16263d; }
.flash.error { border-color:var(--red); background:#2e1820; }
.flash.ok { border-color:var(--green); }
form { display:grid; gap:10px; margin:10px 0; }
form.inline { display:inline; }
label { display:grid; gap:4px; font-size:14px; }
label.check { display:flex; gap:8px; align-items:center; }
input[type=text], input[type=password], input[type=file] {
  background:#0e1828; color:var(--text); border:1px solid var(--line);
  border-radius:7px; padding:9px; }
button { background:#24354e; color:var(--cyan); border:1px solid #38506f;
         border-radius:7px; padding:9px 14px; cursor:pointer; justify-self:start; }
button.ok { color:var(--green); border-color:#2f6b57; }
button.danger { color:var(--red); border-color:#6b3040; }
table { width:100%; border-collapse:collapse; font-size:14px; }
th, td { text-align:left; padding:8px; border-bottom:1px solid #293851;
         vertical-align:top; overflow-wrap:anywhere; }
.pill { display:inline-block; background:#24354e; padding:3px 9px; border-radius:20px; font-size:13px; }
.snap { max-width:100%; border-radius:10px; border:1px solid var(--line); }
.actions { display:flex; gap:12px; flex-wrap:wrap; }
"""

ADMIN_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CYBER ECHO | Owner Security</title>
<style>{{ css|safe }}</style></head>
<body><main>
<h1>Owner Security</h1>
<p><a href="/">Dashboard</a> &middot; <a href="/echotrace">EchoTrace</a> &middot;
   <span class="muted">This page is available only from this device.</span></p>
{% for category, message in get_flashed_messages(with_categories=true) %}
  <div class="flash {{ category }}">{{ message }}</div>
{% endfor %}

<section class="panel">
  <h2>1. Owner profile</h2>
  {% if configured %}
    <p>Passphrase: <span class="pill">set</span> &nbsp; Enrolled photos: <strong>{{ face_count }}</strong>
       &nbsp; Face models: <strong>{{ 'found' if models_ok else 'MISSING (see README)' }}</strong></p>
    <p>Owner email: <strong>{{ recipients }}</strong> recipient(s),
       {{ 'configured' if email_ready else 'NOT configured' }}</p>
    <form method="post" action="/security/enroll" enctype="multipart/form-data">
      <h2>Replace enrolled photos</h2>
      <label>Owner passphrase<input type="password" name="passphrase" required></label>
      <label>New photos (one face per photo)<input type="file" name="photos" accept="image/*" multiple required></label>
      <button type="submit">Replace photos</button>
    </form>
  {% else %}
    <p>Set your owner passphrase and enroll 3 to 5 clear photos of your face in different light.
       The face check cannot run until this is done.</p>
    <form method="post" action="/security/setup" enctype="multipart/form-data">
      <label>Owner passphrase (at least 12 characters)<input type="password" name="passphrase" minlength="12" required></label>
      <label>Repeat passphrase<input type="password" name="passphrase2" minlength="12" required></label>
      <label>Owner photos (one face per photo)<input type="file" name="photos" accept="image/*" multiple required></label>
      <button type="submit">Save owner profile</button>
    </form>
    <p class="muted">Write the passphrase down somewhere safe. Protected files cannot be recovered without it.</p>
  {% endif %}
</section>

<section class="panel">
  <h2>2. Protect a private file</h2>
  <p class="muted">The file is encrypted into the vault and checked. Only then is the original deleted.
     Keep backups of important files.</p>
  <form method="post" action="/security/protect">
    <label>Full path of the file<input type="text" name="path" placeholder="C:\\Users\\you\\Documents\\private.docx" required></label>
    <label>Owner passphrase<input type="password" name="passphrase" required></label>
    <label class="check"><input type="checkbox" name="confirm" value="yes" required>
      I understand the original is deleted after the encrypted copy is verified, and the passphrase cannot be recovered.</label>
    <button type="submit">Protect file</button>
  </form>
</section>

<section class="panel">
  <h2>3. Protected files</h2>
  <form method="post" action="/security/lock-all" class="inline"><button class="danger" type="submit">Lock all now</button></form>
  {% if files %}
  <table>
    <thead><tr><th>#</th><th>File</th><th>State</th><th>Open until</th><th>Open a copy for me</th></tr></thead>
    <tbody>
    {% for f in files %}
      <tr>
        <td>{{ f.id }}</td>
        <td>{{ f.file_name }}</td>
        <td><span class="pill">{{ f.state }}</span>
          {% if f.granted_path %}<div class="muted">{{ f.granted_path }}</div>{% endif %}</td>
        <td>{{ f.grant_expires_at or '' }}</td>
        <td>
          {% if f.state == 'LOCKED' %}
            <form method="post" action="/security/open/{{ f.id }}">
              <input type="password" name="passphrase" placeholder="passphrase" required>
              <button type="submit">Open read-only copy</button>
            </form>
          {% else %}
            <form method="post" action="/security/lock/{{ f.id }}">
              <button class="danger" type="submit">Lock now</button>
            </form>
          {% endif %}
          <form method="post" action="/security/restore/{{ f.id }}">
            <input type="password" name="passphrase" placeholder="passphrase" required>
            <button class="ok" type="submit">Restore to original place</button>
          </form>
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
    <p class="muted">No protected files yet.</p>
  {% endif %}
</section>

<section class="panel">
  <h2>4. Access requests</h2>
  {% if requests %}
  <table>
    <thead><tr><th>#</th><th>Created</th><th>Status</th><th>Wrong passphrase tries</th><th>Decision</th><th>Photo</th></tr></thead>
    <tbody>
    {% for r in requests %}
      <tr>
        <td>{{ r.id }}</td>
        <td>{{ r.created_at }}</td>
        <td><span class="pill">{{ r.status }}</span></td>
        <td>{{ r.attempts }}</td>
        <td>{{ r.decision_note or '' }}</td>
        <td>{% if r.snapshot_path %}<a href="/security/snapshot/{{ r.id }}">view</a>{% endif %}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
    <p class="muted">No access requests yet.</p>
  {% endif %}
</section>

<section class="panel">
  <h2>5. Recent face checks</h2>
  <p class="muted">Checks run at logon and every {{ check_minutes }} minutes while face_guard.py runs.
     Threat notifications sent so far: {{ threats }}.</p>
  {% if checks %}
  <table>
    <thead><tr><th>Time</th><th>Result</th><th>Best match</th><th>Faces</th></tr></thead>
    <tbody>
    {% for c in checks %}
      <tr>
        <td>{{ c.checked_at }}</td>
        <td>{{ c.result }}</td>
        <td>{{ "%.3f"|format(c.best_score) if c.best_score is not none else "-" }}</td>
        <td>{{ c.face_count }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
    <p class="muted">No checks recorded yet. Start face_guard.py.</p>
  {% endif %}
</section>
</main></body></html>
"""

RESPOND_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CYBER ECHO | Access decision</title>
<style>{{ css|safe }}</style></head>
<body><main>
<h1>Unauthorised user decision</h1>
<p class="muted">CYBER ECHO security request</p>
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}

{% if state == "invalid" %}
  <section class="panel"><p>This link is invalid, has expired, or was already used.</p></section>
{% elif state == "done" %}
  <section class="panel"><p>{{ message }}</p></section>
{% else %}
  <section class="panel">
    <p><strong>This user is NOT authorised.</strong> The face at the webcam does not match the enrolled owner.
       Protected files are locked.</p>
    {% if has_snapshot %}<img class="snap" src="{{ snapshot_url }}" alt="Webcam snapshot">{% endif %}
    <form method="post">
      <h2>Protected files you may share</h2>
      {% if files %}
        {% for f in files %}
          <label class="check"><input type="checkbox" name="file_ids" value="{{ f.id }}"> {{ f.file_name }}</label>
        {% endfor %}
      {% else %}
        <p class="muted">No locked protected files are registered.</p>
      {% endif %}
      <label>Your CYBER ECHO passphrase (required for YES)
        <input type="password" name="passphrase" autocomplete="off"></label>
      <div class="actions">
        <button type="submit" name="decision" value="YES" class="ok">YES: grant the selected files</button>
        <button type="submit" name="decision" value="NO" class="danger">NO: keep everything locked</button>
      </div>
    </form>
    <p class="muted">Granted files open as read-only copies for {{ grant_minutes }} minutes, then lock again.
       Changes made to a granted copy are not saved back.</p>
  </section>
{% endif %}
</main></body></html>
"""


ALLOWED_ORIGINS = ("http://127.0.0.1:", "http://localhost:")


@security_bp.before_request
def admin_pages_are_local_only():
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if request.remote_addr not in LOCAL_ADDRESSES:
        abort(403)
    # A web page open in this browser can make the browser send requests to
    # 127.0.0.1. Refuse form posts that come from another site.
    if request.method == "POST":
        origin = request.headers.get("Origin")
        if origin and not origin.startswith(ALLOWED_ORIGINS):
            abort(403)
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            abort(403)
    return None


def _notify_owner(title, text):
    device = notifier.device_name()
    subject = f"[CYBER ECHO] {title} on {device}"
    body = f"{text}\n\nDevice: {device}\nTime  : {store.stamp()}\n"
    ok, info = notifier.send_email(subject, body)
    if not ok:
        print(f"[EMAIL] Not sent: {info}")


def _safe_snapshot(path):
    if not path:
        return False
    root = os.path.abspath(store.SNAPSHOT_DIR) + os.sep
    return os.path.abspath(path).startswith(root) and os.path.isfile(path)


def _enroll_uploads(files):
    blobs = [item.read() for item in files if item and item.filename]
    if not blobs:
        raise face_guard.EnrollmentError("Upload at least one clear photo of your face.")
    return face_guard.enroll_from_images(blobs)


# ----- Admin page (this device only) -----

@security_bp.route("/security")
def admin_page():
    return render_template_string(
        ADMIN_HTML,
        css=CSS,
        configured=store.owner_configured(),
        face_count=len(store.get_owner_features()),
        models_ok=face_guard.models_present(),
        email_ready=notifier.is_configured(),
        recipients=len(notifier.settings()["recipients"]),
        files=store.list_protected(),
        requests=store.list_requests(),
        checks=store.list_face_checks(),
        threats=store.count_threats_seen(),
        check_minutes=face_guard.CHECK_MINUTES,
    )


@security_bp.route("/security/setup", methods=["POST"])
def setup():
    if store.owner_configured():
        flash("The owner profile already exists. Use Replace photos with your passphrase.", "error")
        return redirect(url_for("security.admin_page"))
    first = request.form.get("passphrase", "")
    second = request.form.get("passphrase2", "")
    if first != second:
        flash("The two passphrases do not match.", "error")
        return redirect(url_for("security.admin_page"))
    if len(first) < store.MIN_PASSPHRASE:
        flash(f"Use at least {store.MIN_PASSPHRASE} characters for the passphrase.", "error")
        return redirect(url_for("security.admin_page"))
    try:
        features = _enroll_uploads(request.files.getlist("photos"))
        store.create_passphrase(first)
        store.replace_owner_features(features)
    except (face_guard.EnrollmentError, face_guard.ModelsMissing, ValueError) as error:
        flash(str(error), "error")
        return redirect(url_for("security.admin_page"))
    flash(f"Owner profile saved with {len(features)} photo(s). You can now protect files.", "ok")
    return redirect(url_for("security.admin_page"))


@security_bp.route("/security/enroll", methods=["POST"])
def enroll():
    if not store.verify_passphrase(request.form.get("passphrase", "")):
        flash("Wrong passphrase.", "error")
        return redirect(url_for("security.admin_page"))
    try:
        features = _enroll_uploads(request.files.getlist("photos"))
    except (face_guard.EnrollmentError, face_guard.ModelsMissing) as error:
        flash(str(error), "error")
        return redirect(url_for("security.admin_page"))
    store.replace_owner_features(features)
    flash(f"Replaced the enrolled photos. {len(features)} photo(s) saved.", "ok")
    return redirect(url_for("security.admin_page"))


@security_bp.route("/security/protect", methods=["POST"])
def protect():
    path = (request.form.get("path") or "").strip().strip('"')
    if request.form.get("confirm") != "yes":
        flash("Tick the confirmation box before protecting a file.", "error")
        return redirect(url_for("security.admin_page"))
    try:
        vault.protect_file(path, request.form.get("passphrase", ""))
    except (vault.VaultError, OSError) as error:
        flash(str(error), "error")
    else:
        flash("File protected. The original was deleted after the encrypted copy was verified.", "ok")
    return redirect(url_for("security.admin_page"))


@security_bp.route("/security/open/<int:file_id>", methods=["POST"])
def open_copy(file_id):
    try:
        granted = vault.grant_files(
            [file_id], request.form.get("passphrase", ""), face_guard.GRANT_MINUTES
        )
    except vault.VaultError as error:
        flash(str(error), "error")
    else:
        if granted:
            flash(
                f"Read-only copy ready for {face_guard.GRANT_MINUTES} minutes: {granted[0]['path']}",
                "ok",
            )
        else:
            flash("That file is no longer in the vault.", "error")
    return redirect(url_for("security.admin_page"))


@security_bp.route("/security/restore/<int:file_id>", methods=["POST"])
def restore_one(file_id):
    try:
        restored = vault.restore_file(file_id, request.form.get("passphrase", ""))
    except vault.VaultError as error:
        flash(str(error), "error")
    else:
        flash(f"Restored to its original place and removed from the vault: {restored}", "ok")
    return redirect(url_for("security.admin_page"))


@security_bp.route("/security/lock/<int:file_id>", methods=["POST"])
def lock_one(file_id):
    try:
        vault.lock_file(file_id)
        flash("File locked.", "ok")
    except vault.VaultError as error:
        flash(str(error), "error")
    return redirect(url_for("security.admin_page"))


@security_bp.route("/security/lock-all", methods=["POST"])
def lock_everything():
    count = vault.lock_all("locked from the owner page")
    flash(f"Locked {count} open file(s).", "ok")
    return redirect(url_for("security.admin_page"))


@security_bp.route("/security/snapshot/<int:request_id>")
def admin_snapshot(request_id):
    row = store.get_request(request_id)
    if row is None or not _safe_snapshot(row["snapshot_path"]):
        abort(404)
    return send_file(row["snapshot_path"], mimetype="image/jpeg")


# ----- Approval page (opened from the owner's email) -----

def _render_respond(**context):
    context.setdefault("state", "form")
    context.setdefault("error", "")
    context.setdefault("message", "")
    context.setdefault("files", [])
    context.setdefault("has_snapshot", False)
    context.setdefault("snapshot_url", "")
    context.setdefault("grant_minutes", face_guard.GRANT_MINUTES)
    return render_template_string(RESPOND_HTML, css=CSS, **context)


def _respond_form(req, token, error=""):
    return {
        "state": "form",
        "error": error,
        "files": [item for item in store.list_protected() if item["state"] == "LOCKED"],
        "has_snapshot": bool(req.get("snapshot_path")),
        "snapshot_url": url_for("security.respond_snapshot", token=token),
        "grant_minutes": face_guard.GRANT_MINUTES,
    }


@security_bp.route("/security/respond/<token>", methods=["GET", "POST"])
def respond(token):
    req = store.find_pending(token)
    if req is None:
        return _render_respond(state="invalid")
    if request.method == "GET":
        return _render_respond(**_respond_form(req, token))

    decision = (request.form.get("decision") or "").upper()
    if decision == "NO":
        store.finish_request(req["id"], "DENIED", "Owner answered NO. Protected files stay locked.")
        _notify_owner(
            "Access DENIED",
            "The owner answered NO. The unauthorised user stays blocked and protected files stay locked.",
        )
        return _render_respond(state="done", message="Recorded: access DENIED. Protected files stay locked.")

    if decision != "YES":
        return _render_respond(**_respond_form(req, token, "Choose YES or NO."))

    file_ids = [int(value) for value in request.form.getlist("file_ids") if value.isdigit()]
    if not file_ids:
        return _render_respond(**_respond_form(req, token, "Select at least one protected file, or answer NO."))

    try:
        granted = vault.grant_files(file_ids, request.form.get("passphrase", ""), face_guard.GRANT_MINUTES)
    except vault.PassphraseError:
        tries = store.increment_attempts(req["id"])
        if tries >= store.MAX_WRONG_ATTEMPTS:
            store.finish_request(req["id"], "LOCKED_OUT", "Too many wrong passphrase attempts.")
            _notify_owner(
                "Approval link closed",
                "Too many wrong passphrase attempts were entered on the approval page. "
                "The request is closed and protected files stay locked.",
            )
            return _render_respond(
                state="done",
                message="Too many wrong attempts. This request is closed and protected files stay locked.",
            )
        return _render_respond(
            **_respond_form(req, token, f"Wrong passphrase ({tries} of {store.MAX_WRONG_ATTEMPTS} attempts).")
        )
    except vault.VaultError as error:
        return _render_respond(**_respond_form(req, token, str(error)))

    if not granted:
        return _render_respond(**_respond_form(req, token, "None of the selected files are in the vault."))

    expires = store.stamp(datetime.now() + timedelta(minutes=face_guard.GRANT_MINUTES))
    names = ", ".join(item["file_name"] for item in granted)
    store.finish_request(req["id"], "APPROVED", f"Granted: {names}", grant_expires=expires)
    _notify_owner(
        "Access GRANTED",
        f"Granted to the unauthorised user: {names}.\n"
        f"Access ends at {expires}. The copies lock again automatically.",
    )
    return _render_respond(state="done", message=f"Access granted to: {names}. It ends at {expires}.")


@security_bp.route("/security/respond/<token>/snapshot")
def respond_snapshot(token):
    req = store.find_pending(token)
    if req is None or not _safe_snapshot(req["snapshot_path"]):
        abort(404)
    return send_file(req["snapshot_path"], mimetype="image/jpeg")
