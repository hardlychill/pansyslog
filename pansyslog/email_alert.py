"""Email alerting via SMTP."""

import smtplib
import sys
from email.mime.text import MIMEText


def send_email(cfg, subject, body):
    """Send alert email via SMTP. Returns True on success."""
    email_cfg = cfg["email"]
    if not email_cfg.get("enabled"):
        print(f"[EMAIL SKIPPED] Email not enabled. Would have sent:")
        print(f"  To: {email_cfg.get('to', '(none)')}")
        print(f"  Subject: {subject}")
        print(f"  Body: {body}")
        return False

    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = email_cfg["smtp_user"]
    msg["To"] = email_cfg["to"]

    try:
        with smtplib.SMTP(email_cfg["smtp_host"], email_cfg["smtp_port"]) as server:
            server.starttls()
            server.login(email_cfg["smtp_user"], email_cfg["smtp_pass"])
            server.sendmail(email_cfg["smtp_user"], [email_cfg["to"]], msg.as_string())
        print(f"[EMAIL SENT] {subject}")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}", file=sys.stderr)
        return False
