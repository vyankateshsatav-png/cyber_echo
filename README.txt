CYBER ECHO - corrected project copy

Files:
- app.py: Flask dashboard and Smart Shield review page
- echotrace.py: read-only incident timeline blueprint
- collector.py and correlation_engine.py: Windows event collection and incident correlation
- process_monitor.py, file_monitor.py, network_monitor.py: monitoring modules
- realtime_monitor.py: event/correlation loop
- auto_response.py: email alerts and Microsoft Defender scan workflow
- test_email.py: standalone email configuration test

Changes made:
1. Removed the duplicate /smart-shield route definition in app.py.
2. Made the SQLite database path consistent across modules. By default, it is
   cyber_echo.db beside these Python files; CYBER_ECHO_DATABASE can override it.
3. Added a Flask secret key fallback so flash/session features do not fail locally.
4. Added requirements.txt for the external dependencies.

Important:
- Python syntax compilation passed for all supplied Python files.
- Runtime integration has not been fully verified here. Run on Windows, because
  Windows Security Event Log and Microsoft Defender features rely on Windows.
- Install dependencies with: py -m pip install -r requirements.txt
- Start the dashboard with: py app.py
- Start the realtime engine separately with: py realtime_monitor.py
- Run monitors separately as needed: py process_monitor.py, py file_monitor.py,
  py network_monitor.py
- Run auto_response.py only after reviewing its alert/email/Defender behavior.
- Set CYBER_ECHO_EMAIL_FROM, CYBER_ECHO_EMAIL_TO, CYBER_ECHO_EMAIL_PASSWORD,
  and CYBER_ECHO_SMTP_HOST before using email features. Do not hard-code secrets.
- Test on a machine you own or are authorized to monitor.
