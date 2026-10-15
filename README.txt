CYBER ECHO - owner security update
==================================

WHAT IT DOES
- Monitors Windows security events, processes, files and network connections.
- Emails you about medium and high incidents (auto_response.py).
- Emails you about Microsoft Defender threat detections (face_guard.py checks every 5 minutes).
- Face check: at logon and every 10 minutes, the webcam compares the person in front of it
  with your enrolled photos.
- If the face does not match: protected files are locked, a snapshot is saved, and you get
  an email with the photo and the question "Do you want to grant access?" with YES / NO.
- YES: you choose which protected files to share and enter your passphrase. Those files open
  as read-only copies for a limited time, then lock again.
- NO, or no answer: protected files stay locked.

READ THESE LIMITS BEFORE RELYING ON IT
1. Face recognition is an alarm, not a lock. The real protection of protected files is the
   encryption. Without your passphrase, nobody can read the vault.
2. The face check runs at logon and on a timer. It cannot check the Windows sign-in screen.
   Anyone who knows your Windows password can sign in before the first check runs.
   Use a strong Windows password.
3. While access is open, the file exists as a plain read-only copy in the "granted" folder.
   Changes made to a granted copy are not saved back. Keep the vault original as the master.
4. Protected originals are deleted after they are encrypted and verified. A lost passphrase
   cannot be recovered. Keep backups of important files. To take a file out of the vault for
   good, use "Restore to original place" on /security (needs the passphrase). Changing the
   passphrase is not supported in this version.
5. The dashboard listens on 127.0.0.1 only. The approval links work from your phone only if
   CYBER_ECHO_APPROVAL_URL points to a private address you control (for example a private
   network tool that forwards to this PC's port 5000). Never expose the dashboard to the internet.
6. Face checks can be wrong. Glasses, a new haircut or poor light can cause a false alarm.
   A false alarm only sends you an email and locks protected files. Re-open them with your
   passphrase on the /security page.
7. Use this on a device you own. Webcam photos and face data are personal data. Tell the people
   who use the computer that it takes photos at logon. Snapshots are kept in the "snapshots"
   folder; delete old ones you no longer need.

INSTALL
  py -m pip install -r requirements.txt

FACE MODELS (one-time download)
Create a folder named "models" inside the project folder and place these two files in it,
with exactly these names:
  face_detection_yunet_2023mar.onnx
  face_recognition_sface_2021dec.onnx
Both come from the OpenCV Zoo project on GitHub (folders face_detection_yunet and
face_recognition_sface under models/). Check the file names after downloading.
Without these files the app still runs; the face check reports MODELS_MISSING.

EMAIL SETTINGS
Set these as USER environment variables (Windows search: "Edit environment variables for your
account"). Sign out and back in afterwards.
  CYBER_ECHO_EMAIL_FROM        sender address
  CYBER_ECHO_EMAIL_TO          owner address(es), comma-separated
  CYBER_ECHO_EMAIL_PASSWORD    SMTP / app password (never write it into a file)
  CYBER_ECHO_SMTP_HOST         for example smtp.gmail.com
  CYBER_ECHO_SMTP_PORT         587
Test: py test_email.py

OTHER SETTINGS (optional environment variables)
  CYBER_ECHO_APPROVAL_URL            default http://127.0.0.1:5000
  CYBER_ECHO_CHECK_MINUTES           default 10   (face check interval)
  CYBER_ECHO_THREAT_CHECK_MINUTES    default 5    (Defender check interval)
  CYBER_ECHO_COOLDOWN_MINUTES        default 30   (minimum time between two owner emails)
  CYBER_ECHO_GRANT_MINUTES           default 60   (how long granted access stays open)
  CYBER_ECHO_CAMERA_INDEX            default 0
  CYBER_ECHO_AUTO_DEFENDER_SCAN      default 0    (set 1 to allow automatic Defender Quick Scans)
  CYBER_ECHO_DATABASE, CYBER_ECHO_DATA_DIR   advanced: move the database or data folders

FIRST-TIME SETUP
1. Start the dashboard:  py app.py
   Open http://127.0.0.1:5000/security
2. Set the owner passphrase (12+ characters) and upload 3 to 5 clear photos of your face,
   one face per photo, in different light.
3. Protect a file: type its full path, enter the passphrase, and tick the confirmation box.
   The file is encrypted, checked, and only then is the original deleted.
4. Start the face guard once by hand:  py face_guard.py
   Sit in front of the camera. The log should say "Owner check: AUTHORIZED".

RUN AT LOGON (Task Scheduler)
1. Press Win+R, type taskschd.msc, press Enter. Choose "Create Task..." (not "Basic").
2. General tab: name it "CYBER ECHO Face Guard". Tick "Run with highest privileges".
3. Triggers tab: New, "Begin the task: At log on", select your user.
4. Actions tab: New, "Start a program".
   Program/script: the full path of py.exe (run "where py" in a terminal).
   Add arguments:  face_guard.py
   Start in:       the full path of this project folder
5. Conditions tab: untick "Start the task only if the computer is on AC power" on laptops.
6. Optional: create the same kind of task for "app.py" so the dashboard starts at logon.

RUN MANUALLY
  py app.py                  dashboard and owner page        http://127.0.0.1:5000/
  py face_guard.py           webcam face check and threat watch
  py realtime_monitor.py     Windows security events and correlation (run as Administrator)
  py process_monitor.py      running processes
  py file_monitor.py         file changes in Desktop, Downloads and Documents
  py network_monitor.py      outbound network connections
  py auto_response.py        emails for correlated incidents

AUTO RESPONSE NOTES
- On the first run, existing alerts are skipped and only new alerts are emailed.
  Delete auto_response_last_alert.txt to reset this.
- A failed or missing email never blocks other alerts. Failures are written to notify_failures.log.
- Automatic Defender Quick Scans are off unless CYBER_ECHO_AUTO_DEFENDER_SCAN=1.

PROCESS MONITOR NOTE
A process that starts and stops between two 3-second scans is not recorded.

ECHOTRACE
Open http://127.0.0.1:5000/echotrace. The database is opened read-only, so EchoTrace cannot
change incident records.

TESTS
  py -m unittest discover -s tests -v
The 39 tests cover the vault, the YES/NO decision rules, the approval pages, cooldowns and
approved windows, threat emails, cross-site protection, and the bug fixes. They use temporary
data and send no real email.

They do NOT test a real webcam, real face models, a real SMTP server, or Windows Defender.

MANUAL CHECKLIST (on your Windows PC)
1. Owner setup works and the log shows AUTHORIZED when you sit in front of the camera.
2. Have someone else sit in front of the camera. Within the next check (or run face_guard.py
   again) an email arrives with the snapshot and the YES/NO link.
3. Answer NO. The Protected files table on /security shows LOCKED.
4. Next request: enter a wrong passphrase once, then the right one, and select one file.
   Only that file appears as an open read-only copy.
5. Wait for the grant to expire, or set CYBER_ECHO_GRANT_MINUTES=2 for the test. The copy is removed.
6. Run test_email.py and confirm the email arrives.
7. Check that Windows Defender detections reach you. Do not test with real malware; use
   the email test and review the threat email format.
