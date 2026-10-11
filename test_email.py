import os
import smtplib
from email.message import EmailMessage


sender = os.environ.get("CYBER_ECHO_EMAIL_FROM")
recipient = os.environ.get("CYBER_ECHO_EMAIL_TO")
password = os.environ.get("CYBER_ECHO_EMAIL_PASSWORD")
smtp_host = os.environ.get("CYBER_ECHO_SMTP_HOST")
smtp_port = int(
    os.environ.get("CYBER_ECHO_SMTP_PORT", "587")
)


print()
print("======================================")
print("       CYBER ECHO EMAIL TEST")
print("======================================")
print()

# Check configuration without showing the password
missing = []

if not sender:
    missing.append("CYBER_ECHO_EMAIL_FROM")

if not recipient:
    missing.append("CYBER_ECHO_EMAIL_TO")

if not password:
    missing.append("CYBER_ECHO_EMAIL_PASSWORD")

if not smtp_host:
    missing.append("CYBER_ECHO_SMTP_HOST")


if missing:
    print("Missing email settings:")
    for item in missing:
        print(" -", item)

    print()
    print("Close this terminal, open a NEW CMD terminal,")
    print("and set the missing variables first.")
    raise SystemExit(1)


message = EmailMessage()

message["From"] = sender
message["To"] = recipient
message["Subject"] = "CYBER ECHO - Email Test"

message.set_content("""
CYBER ECHO EMAIL TEST

This is a test message from your CYBER ECHO
security-monitoring system.

Email configuration is working.

No threat was detected.
No security action was taken.

CYBER ECHO
""")


try:

    print("Connecting to mail server...")

    with smtplib.SMTP(
        smtp_host,
        smtp_port,
        timeout=30
    ) as smtp:

        smtp.starttls()

        print("Logging in...")

        smtp.login(
            sender,
            password
        )

        print("Sending test email...")

        smtp.send_message(message)

    print()
    print("✅ TEST EMAIL SENT SUCCESSFULLY")
    print()
    print("Check the recipient inbox.")
    print("Also check Spam/Junk if necessary.")

except Exception as error:

    print()
    print("❌ EMAIL TEST FAILED")
    print()
    print("Error:")
    print(error)