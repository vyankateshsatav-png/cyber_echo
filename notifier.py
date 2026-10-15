"""Email sending shared by CYBER ECHO modules.

Uses these environment variables (set them once as user environment variables,
never inside a file in the project):

  CYBER_ECHO_EMAIL_FROM       sender address (also used as the SMTP login)
  CYBER_ECHO_EMAIL_TO         owner address(es), separated by commas
  CYBER_ECHO_EMAIL_PASSWORD   SMTP password or app password
  CYBER_ECHO_SMTP_HOST        for example smtp.gmail.com
  CYBER_ECHO_SMTP_PORT        default 587 (STARTTLS)
"""

import mimetypes
import os
import smtplib
import socket
from email.message import EmailMessage


def _port():
    try:
        return int(os.environ.get("CYBER_ECHO_SMTP_PORT", "587") or 587)
    except ValueError:
        return 587


def settings():
    recipients = os.environ.get("CYBER_ECHO_EMAIL_TO", "")
    return {
        "sender": os.environ.get("CYBER_ECHO_EMAIL_FROM", "").strip(),
        "recipients": [item.strip() for item in recipients.split(",") if item.strip()],
        "password": os.environ.get("CYBER_ECHO_EMAIL_PASSWORD", ""),
        "host": os.environ.get("CYBER_ECHO_SMTP_HOST", "").strip(),
        "port": _port(),
    }


def is_configured():
    current = settings()
    return bool(
        current["sender"]
        and current["recipients"]
        and current["password"]
        and current["host"]
    )


def device_name():
    return socket.gethostname()


def send_email(subject, body, attachments=()):
    """Send a plain-text email with optional file attachments.

    Returns (ok, message). Normal failures are returned, not raised.
    """
    if not is_configured():
        return False, "Email is not configured. Set the CYBER_ECHO_EMAIL_* variables."

    current = settings()
    message = EmailMessage()
    message["From"] = current["sender"]
    message["To"] = ", ".join(current["recipients"])
    message["Subject"] = subject
    message.set_content(body)

    try:
        for path in attachments:
            kind = mimetypes.guess_type(path)[0] or "application/octet-stream"
            main_type, sub_type = kind.split("/", 1)
            with open(path, "rb") as handle:
                message.add_attachment(
                    handle.read(),
                    maintype=main_type,
                    subtype=sub_type,
                    filename=os.path.basename(path),
                )

        with smtplib.SMTP(current["host"], current["port"], timeout=30) as smtp:
            smtp.starttls()
            smtp.login(current["sender"], current["password"])
            smtp.send_message(message)
        return True, "sent"

    except (smtplib.SMTPException, OSError) as error:
        return False, str(error)
