"""Tests for CYBER ECHO owner security and the bug fixes.

Run from the project folder:
    py -m unittest discover -s tests -v
(Linux or macOS: python3 -m unittest discover -s tests -v)

These tests use a temporary database and a temporary data folder, and they never
send real email. They do NOT test a real webcam, real face models, real SMTP
servers, or Windows Defender. Those are covered by the manual checklist in README.txt.
"""

import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest import mock

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMP = tempfile.mkdtemp(prefix="cyber_echo_tests_")
os.environ["CYBER_ECHO_DATABASE"] = os.path.join(TEMP, "test.db")
os.environ["CYBER_ECHO_DATA_DIR"] = os.path.join(TEMP, "data")
for _name in ("CYBER_ECHO_EMAIL_FROM", "CYBER_ECHO_EMAIL_TO",
              "CYBER_ECHO_EMAIL_PASSWORD", "CYBER_ECHO_SMTP_HOST"):
    os.environ.pop(_name, None)
sys.path.insert(0, PROJECT)

import numpy as np  # noqa: E402

import app as app_module  # noqa: E402
import auto_response  # noqa: E402
import echotrace  # noqa: E402
import face_guard  # noqa: E402
import notifier  # noqa: E402
import process_monitor  # noqa: E402
import security_store as store  # noqa: E402
import threat_watch  # noqa: E402
import vault  # noqa: E402

PASSPHRASE = "owner-passphrase-123"


class FakeMail:
    """Records emails instead of sending them."""

    def __init__(self):
        self.sent = []

    def __call__(self, subject, body, attachments=()):
        self.sent.append((subject, body, list(attachments)))
        return True, "sent"


def install_fake_mail(test):
    fake = FakeMail()
    patcher = mock.patch.object(notifier, "send_email", fake)
    patcher.start()
    test.addCleanup(patcher.stop)
    return fake


def reset_state():
    with store.db() as conn:
        for table in store.TABLES:
            conn.execute(f"DELETE FROM {table}")
    for folder in (store.VAULT_DIR, store.GRANTED_DIR, store.SNAPSHOT_DIR):
        shutil.rmtree(folder, ignore_errors=True)


def write_file(folder, name, data):
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


class TestSetup(unittest.TestCase):
    def setUp(self):
        reset_state()

    def test_short_passphrase_is_refused(self):
        with self.assertRaises(ValueError):
            store.create_passphrase("short")
        self.assertFalse(store.owner_configured())

    def test_passphrase_unlocks_only_with_the_right_value(self):
        store.create_passphrase(PASSPHRASE)
        self.assertIsNotNone(store.unlock_key(PASSPHRASE))
        self.assertIsNone(store.unlock_key("wrong-passphrase-999"))
        self.assertTrue(store.verify_passphrase(PASSPHRASE))
        self.assertFalse(store.verify_passphrase(""))

    def test_passphrase_is_set_only_once(self):
        store.create_passphrase(PASSPHRASE)
        with self.assertRaises(RuntimeError):
            store.create_passphrase("another-long-passphrase")


class TestVault(unittest.TestCase):
    def setUp(self):
        reset_state()
        store.create_passphrase(PASSPHRASE)
        self.workdir = tempfile.mkdtemp(dir=TEMP)

    def make(self, name="diary.txt", data=b"secret notes"):
        return write_file(self.workdir, name, data)

    def test_protect_grant_and_lock_cycle(self):
        original = self.make()
        file_id = vault.protect_file(original, PASSPHRASE)
        self.assertFalse(os.path.exists(original), "original must be deleted after protection")
        self.assertEqual(store.get_protected(file_id)["state"], "LOCKED")

        granted = vault.grant_files([file_id], PASSPHRASE, 30)[0]
        with open(granted["path"], "rb") as handle:
            self.assertEqual(handle.read(), b"secret notes")
        self.assertEqual(stat.S_IMODE(os.stat(granted["path"]).st_mode) & stat.S_IWUSR, 0,
                         "granted copy must be read-only")
        self.assertEqual(store.get_protected(file_id)["state"], "GRANTED")

        vault.lock_file(file_id)
        self.assertFalse(os.path.exists(granted["path"]), "open copy must be removed on lock")
        self.assertEqual(store.get_protected(file_id)["state"], "LOCKED")
        self.assertFalse(os.path.exists(original))

    def test_wrong_passphrase_cannot_open(self):
        file_id = vault.protect_file(self.make(), PASSPHRASE)
        with self.assertRaises(vault.PassphraseError):
            vault.grant_files([file_id], "wrong-passphrase-999", 30)
        self.assertEqual(store.get_protected(file_id)["state"], "LOCKED")

    def test_expired_access_is_locked_by_sweep(self):
        file_id = vault.protect_file(self.make(), PASSPHRASE)
        granted = vault.grant_files([file_id], PASSPHRASE, -1)[0]
        vault.sweep_expired()
        self.assertFalse(os.path.exists(granted["path"]))
        self.assertEqual(store.get_protected(file_id)["state"], "LOCKED")

    def test_files_inside_the_project_are_refused(self):
        inside = os.path.join(PROJECT, "tests", "_inside_project_check.txt")
        with open(inside, "wb") as handle:
            handle.write(b"x")
        self.addCleanup(lambda: os.path.exists(inside) and os.remove(inside))
        with self.assertRaises(vault.VaultError):
            vault.protect_file(inside, PASSPHRASE)
        self.assertTrue(os.path.exists(inside))

    def test_same_path_cannot_be_protected_twice(self):
        path = self.make()
        vault.protect_file(path, PASSPHRASE)
        again = self.make()  # a new file with the same name in the same folder
        with self.assertRaises(vault.VaultError):
            vault.protect_file(again, PASSPHRASE)


class TestRestore(unittest.TestCase):
    def setUp(self):
        reset_state()
        store.create_passphrase(PASSPHRASE)
        self.workdir = tempfile.mkdtemp(dir=TEMP)

    def test_restore_puts_file_back_and_leaves_vault(self):
        original = write_file(self.workdir, "contract.txt", b"signed terms")
        file_id = vault.protect_file(original, PASSPHRASE)
        vault_copy = store.get_protected(file_id)["vault_path"]
        restored = vault.restore_file(file_id, PASSPHRASE)
        self.assertEqual(restored, original)
        with open(original, "rb") as handle:
            self.assertEqual(handle.read(), b"signed terms")
        self.assertIsNone(store.get_protected(file_id))
        self.assertFalse(os.path.exists(vault_copy))

    def test_restore_needs_passphrase_and_never_overwrites(self):
        original = write_file(self.workdir, "notes.txt", b"v1")
        file_id = vault.protect_file(original, PASSPHRASE)
        with self.assertRaises(vault.PassphraseError):
            vault.restore_file(file_id, "wrong-passphrase-999")
        self.assertEqual(store.get_protected(file_id)["state"], "LOCKED")
        write_file(self.workdir, "notes.txt", b"someone else's file")
        with self.assertRaises(vault.VaultError):
            vault.restore_file(file_id, PASSPHRASE)
        self.assertIsNotNone(store.get_protected(file_id))


class TestDecisions(unittest.TestCase):
    def test_decision_rules(self):
        self.assertEqual(face_guard.decide([]), "NO_FACE")
        self.assertEqual(face_guard.decide([0.9]), "AUTHORIZED")
        self.assertEqual(face_guard.decide([0.363]), "AUTHORIZED")
        self.assertEqual(face_guard.decide([0.2]), "UNAUTHORIZED")
        self.assertEqual(face_guard.decide([0.9, 0.1]), "UNAUTHORIZED",
                         "the owner plus a stranger in one frame must count as unauthorised")


class TestAccessRequests(unittest.TestCase):
    def setUp(self):
        reset_state()

    def test_token_works_only_while_pending(self):
        token = store.new_token()
        request_id = store.create_request(store.hash_token(token), None, 24, 0.1)
        self.assertIsNotNone(store.find_pending(token))
        store.finish_request(request_id, "DENIED", "no")
        self.assertIsNone(store.find_pending(token))

    def test_expired_request_is_not_found(self):
        token = store.new_token()
        store.create_request(store.hash_token(token), None, -1, 0.1)
        self.assertIsNone(store.find_pending(token))

    def test_approved_window_ends_at_its_expiry(self):
        token = store.new_token()
        request_id = store.create_request(store.hash_token(token), None, 24, 0.1)
        future = store.stamp(datetime.now() + timedelta(minutes=30))
        store.finish_request(request_id, "APPROVED", "ok", grant_expires=future)
        self.assertTrue(store.approved_grant_active())
        past = store.stamp(datetime.now() - timedelta(minutes=1))
        with store.db() as conn:
            conn.execute("UPDATE access_requests SET grant_expires_at = ?", (past,))
        self.assertFalse(store.approved_grant_active())


class TestGuardFlow(unittest.TestCase):
    def setUp(self):
        reset_state()
        store.create_passphrase(PASSPHRASE)
        self.mail = install_fake_mail(self)
        self.frame = np.zeros((120, 160, 3), dtype=np.uint8)
        self.file_id = vault.protect_file(
            write_file(os.path.join(TEMP, "guard_files"), "letters.txt", b"private"), PASSPHRASE
        )

    def test_unauthorized_sends_one_question_while_waiting(self):
        face_guard.handle_result("UNAUTHORIZED", 0.12, 2, self.frame)
        face_guard.handle_result("UNAUTHORIZED", 0.11, 2, self.frame)
        self.assertEqual(len(store.list_requests()), 1)
        self.assertEqual(len(self.mail.sent), 1)
        subject, body, attachments = self.mail.sent[0]
        self.assertIn("UNAUTHORIZED", subject)
        self.assertIn("do you grant access", subject.lower())
        self.assertIn("NOT authorised", body)
        self.assertIn("/security/respond/", body)
        self.assertTrue(os.path.isfile(attachments[0]), "snapshot must be attached")
        self.assertEqual(store.get_protected(self.file_id)["state"], "LOCKED")

    def test_authorized_check_does_nothing(self):
        face_guard.handle_result("AUTHORIZED", 0.8, 1, self.frame)
        self.assertEqual(store.list_requests(), [])
        self.assertEqual(self.mail.sent, [])

    def test_denied_request_is_not_repeated_inside_cooldown(self):
        face_guard.handle_result("UNAUTHORIZED", 0.12, 2, self.frame)
        request = store.list_requests()[0]
        store.finish_request(request["id"], "DENIED", "no")
        face_guard.handle_result("UNAUTHORIZED", 0.12, 2, self.frame)
        self.assertEqual(len(self.mail.sent), 1)

    def test_approved_window_is_not_locked_again(self):
        token = store.new_token()
        request_id = store.create_request(store.hash_token(token), None, 24, 0.1)
        future = store.stamp(datetime.now() + timedelta(minutes=30))
        store.finish_request(request_id, "APPROVED", "ok", grant_expires=future)
        vault.grant_files([self.file_id], PASSPHRASE, 30)
        face_guard.handle_result("UNAUTHORIZED", 0.12, 2, self.frame)
        self.assertEqual(store.get_protected(self.file_id)["state"], "GRANTED")
        self.assertEqual(self.mail.sent, [])


class TestApprovalPages(unittest.TestCase):
    def setUp(self):
        reset_state()
        store.create_passphrase(PASSPHRASE)
        self.mail = install_fake_mail(self)
        self.folder = os.path.join(TEMP, "approval_files")
        self.file_id = vault.protect_file(write_file(self.folder, "passwords.txt", b"my private list"), PASSPHRASE)
        self.client = app_module.app.test_client()

    def new_request(self):
        token = store.new_token()
        request_id = store.create_request(store.hash_token(token), None, 24, 0.12)
        return token, request_id

    def test_deny_keeps_files_locked_and_link_is_single_use(self):
        token, request_id = self.new_request()
        page = self.client.get(f"/security/respond/{token}")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"NOT authorised", page.data)
        answer = self.client.post(f"/security/respond/{token}", data={"decision": "NO"})
        self.assertEqual(answer.status_code, 200)
        self.assertEqual(store.get_request(request_id)["status"], "DENIED")
        self.assertEqual(store.get_protected(self.file_id)["state"], "LOCKED")
        again = self.client.get(f"/security/respond/{token}")
        self.assertIn(b"invalid", again.data)

    def test_wrong_passphrase_attempts_are_limited(self):
        token, request_id = self.new_request()
        for _ in range(store.MAX_WRONG_ATTEMPTS):
            self.client.post(f"/security/respond/{token}", data={
                "decision": "YES",
                "passphrase": "wrong-guess-value",
                "file_ids": [str(self.file_id)],
            })
        self.assertEqual(store.get_request(request_id)["status"], "LOCKED_OUT")
        self.assertEqual(store.get_protected(self.file_id)["state"], "LOCKED")

    def test_cross_site_form_post_is_refused(self):
        response = self.client.post("/security/lock-all",
                                    headers={"Origin": "https://evil.example"})
        self.assertEqual(response.status_code, 403)
        response = self.client.post("/security/lock-all",
                                    headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(response.status_code, 403)
        response = self.client.post("/security/lock-all",
                                    headers={"Origin": "http://127.0.0.1:5000"})
        self.assertEqual(response.status_code, 302)

    def test_grant_opens_only_the_selected_file(self):
        other_id = vault.protect_file(write_file(self.folder, "photos.txt", b"holiday"), PASSPHRASE)
        token, request_id = self.new_request()
        self.client.post(f"/security/respond/{token}", data={
            "decision": "YES",
            "passphrase": PASSPHRASE,
            "file_ids": [str(self.file_id)],
        })
        self.assertEqual(store.get_request(request_id)["status"], "APPROVED")
        self.assertEqual(store.get_protected(self.file_id)["state"], "GRANTED")
        self.assertEqual(store.get_protected(other_id)["state"], "LOCKED")
        granted_path = store.get_protected(self.file_id)["granted_path"]
        with open(granted_path, "rb") as handle:
            self.assertEqual(handle.read(), b"my private list")
        self.assertTrue(self.mail.sent, "owner must receive a confirmation email")

    def test_admin_page_refuses_remote_clients_but_approval_still_works(self):
        remote = self.client.get("/security", environ_base={"REMOTE_ADDR": "198.51.100.20"})
        self.assertEqual(remote.status_code, 403)
        local = self.client.get("/security")
        self.assertEqual(local.status_code, 200)
        self.assertIn(b"Owner Security", local.data)
        token, _ = self.new_request()
        remote_page = self.client.get(f"/security/respond/{token}",
                                      environ_base={"REMOTE_ADDR": "198.51.100.20"})
        self.assertEqual(remote_page.status_code, 200)


class TestThreatWatch(unittest.TestCase):
    def setUp(self):
        reset_state()
        self.mail = install_fake_mail(self)

    def test_new_detections_skip_ones_already_seen(self):
        items = [{"DetectionId": "1"}, {"DetectionId": "2"}]
        fresh = threat_watch.new_detections(items, is_seen=lambda key: key == "1")
        self.assertEqual([key for key, _ in fresh], ["2"])

    def test_detection_is_emailed_once(self):
        items = [{
            "DetectionId": "d-100",
            "ThreatName": "Test:Sample",
            "Time": "2026-10-14 09:00:00",
            "Process": "sample.exe",
            "Resources": "C:\\Temp\\sample.exe",
            "ActionSuccess": "True",
        }]
        with mock.patch.object(threat_watch, "read_detections", return_value=(items, None)):
            self.assertEqual(threat_watch.check_and_notify(), 1)
            self.assertEqual(threat_watch.check_and_notify(), 0)
        self.assertEqual(len(self.mail.sent), 1)
        self.assertIn("Test:Sample", self.mail.sent[0][1])


class TestBugFixes(unittest.TestCase):
    def setUp(self):
        reset_state()

    def test_smart_shield_route_is_defined_once(self):
        rules = [rule.rule for rule in app_module.app.url_map.iter_rules()]
        self.assertEqual(rules.count("/smart-shield"), 1)

    def test_echotrace_connection_is_read_only(self):
        store.connect().close()
        conn = sqlite3.connect(os.environ["CYBER_ECHO_DATABASE"])
        conn.execute("CREATE TABLE IF NOT EXISTS correlation_alerts (id INTEGER PRIMARY KEY, title TEXT)")
        conn.execute("INSERT INTO correlation_alerts (id, title) VALUES (1, 'test')")
        conn.commit()
        conn.close()
        reader = echotrace.connect_db()
        try:
            self.assertEqual(reader.execute("SELECT COUNT(*) FROM correlation_alerts").fetchone()[0], 1)
            with self.assertRaises(sqlite3.OperationalError):
                reader.execute("INSERT INTO correlation_alerts (id, title) VALUES (2, 'change')")
        finally:
            reader.close()

    def test_reused_process_id_ends_the_old_row(self):
        running = {(100, "2026-10-14 08:00:00"): 7}
        active = {(100, "2026-10-14 09:30:00")}
        self.assertEqual(process_monitor.ended_ids(running, active), [7])

    def test_dashboard_escapes_text_and_shows_totals(self):
        self.assertEqual(app_module.esc("<script>x</script>"), "&lt;script&gt;x&lt;/script&gt;")
        result = app_module.escape_row({"title": "<b>t</b>", "score": 80})
        self.assertEqual(result["title"], "&lt;b&gt;t&lt;/b&gt;")
        self.assertEqual(result["score"], 80)
        response = app_module.app.test_client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Highest Alert Risk", response.data)
        self.assertNotIn(b"Security Score", response.data)

    def test_auto_response_reports_missing_email_settings(self):
        self.assertFalse(auto_response.email_settings_ready())

    def test_notifier_refuses_to_send_when_not_configured(self):
        ok, message = notifier.send_email("subject", "body")
        self.assertFalse(ok)
        self.assertIn("not configured", message)


class TestEndToEnd(unittest.TestCase):
    """Real database rows and real HTTP responses, not mocks."""

    ALERT_SCHEMA = """
        CREATE TABLE correlation_alerts (
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
        )"""

    def setUp(self):
        reset_state()
        conn = sqlite3.connect(os.environ["CYBER_ECHO_DATABASE"])
        for table in ("security_events", "process_events", "file_events",
                      "network_events", "correlation_alerts"):
            conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.execute(self.ALERT_SCHEMA)
        conn.commit()
        conn.close()
        import collector  # real schema for security_events
        collector.init_db()

    def insert_alert(self, title, explanation="Test explanation", score=80, level="HIGH"):
        conn = sqlite3.connect(os.environ["CYBER_ECHO_DATABASE"])
        conn.execute(
            """INSERT INTO correlation_alerts (fingerprint, alert_level, score, title,
               explanation, event_count, first_event_time, last_event_time, created_at)
               VALUES (?, ?, ?, ?, ?, 2, '2026-10-14 09:00:00', '2026-10-14 09:05:00',
               '2026-10-14 09:06:00')""",
            (store.new_token(), level, score, title, explanation),
        )
        conn.commit()
        alert_id = conn.execute("SELECT MAX(id) FROM correlation_alerts").fetchone()[0]
        conn.close()
        return alert_id

    def test_malicious_alert_title_is_escaped_on_dashboard(self):
        self.insert_alert("<script>alert('x')</script>", "<img src=x onerror=alert(1)>")
        response = app_module.app.test_client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"<script>alert", response.data)
        self.assertNotIn(b"<img src=x", response.data)
        self.assertIn(b"&lt;script&gt;alert", response.data)

    def test_dashboard_counts_are_not_capped_at_100(self):
        for number in range(105):
            self.insert_alert(f"Incident {number}")
        conn = sqlite3.connect(os.environ["CYBER_ECHO_DATABASE"])
        conn.executemany(
            """INSERT INTO security_events (record_id, event_id, event_type, description,
               user_name, source_ip, risk, created_at)
               VALUES (?, 4625, 'Failed Logon', 'test', 'user', '10.0.0.1', 20,
               '2026-10-14 09:00:00')""",
            [(str(n),) for n in range(1, 106)],
        )
        conn.commit()
        conn.close()
        self.assertEqual(app_module.count_table("correlation_alerts"), 105)
        self.assertEqual(app_module.count_table("security_events"), 105)
        response = app_module.app.test_client().get("/")
        self.assertIn(b"105", response.data)

    def test_latest_alert_id_reads_the_real_table(self):
        self.insert_alert("First")
        last = self.insert_alert("Second")
        self.assertEqual(auto_response.get_latest_alert_id(), last)

    def test_admin_page_escapes_file_names(self):
        store.create_passphrase(PASSPHRASE)
        folder = os.path.join(TEMP, "escape_files")
        # Windows does not allow < > " | ? * in file names, so use characters it does allow.
        name = "Tom & Jerry's notes.txt"
        vault.protect_file(write_file(folder, name, b"data"), PASSPHRASE)
        response = app_module.app.test_client().get("/security")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"Tom & Jerry", response.data)
        self.assertIn(b"Tom &amp; Jerry", response.data)

class TestProcessMonitorLive(unittest.TestCase):
    """Runs the real process scan against this machine's processes."""

    def setUp(self):
        reset_state()

    def test_scan_records_running_processes_including_this_one(self):
        process_monitor.init_db()
        conn = sqlite3.connect(os.environ["CYBER_ECHO_DATABASE"])
        try:
            known, running = process_monitor.load_state(conn)
            active, new_count = process_monitor.scan_once(conn, known, running)
            conn.commit()
            self.assertGreater(new_count, 0)
            own_pid = os.getpid()
            self.assertTrue(any(pid == own_pid for pid, _ in active))
            rows = conn.execute("SELECT DISTINCT status FROM process_events").fetchall()
            self.assertEqual([row[0] for row in rows], ["RUNNING"])
            # Nothing is active any more: every running row must become ENDED.
            ended = process_monitor.mark_ended(conn, running, set())
            conn.commit()
            self.assertEqual(ended, new_count)
            left = conn.execute(
                "SELECT COUNT(*) FROM process_events WHERE status = 'RUNNING'"
            ).fetchone()[0]
            self.assertEqual(left, 0)
        finally:
            conn.close()


class TestFaceModelsMissing(unittest.TestCase):
    def setUp(self):
        reset_state()
        face_guard._engine = None

    def test_guard_reports_missing_models_instead_of_crashing(self):
        with mock.patch.object(store, "MODELS_DIR", os.path.join(TEMP, "no_models_here")):
            with self.assertRaises(face_guard.ModelsMissing):
                face_guard.get_engine()
            self.assertFalse(face_guard.models_present())

    def test_no_owner_profile_means_no_check(self):
        result = face_guard.run_owner_check()
        self.assertEqual(result[0], "NOT_ENROLLED")

    def test_enrollment_without_models_is_a_clear_error(self):
        store.create_passphrase(PASSPHRASE)
        with mock.patch.object(store, "MODELS_DIR", os.path.join(TEMP, "no_models_here")):
            with self.assertRaises(face_guard.ModelsMissing):
                face_guard.enroll_from_images([b"\x89PNG fake"])


if __name__ == "__main__":
    unittest.main()
