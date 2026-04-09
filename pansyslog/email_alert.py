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

    sender = email_cfg.get("smtp_user") or email_cfg.get("from", f"pansyslog@{email_cfg['smtp_host']}")
    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = email_cfg["to"]

    try:
        with smtplib.SMTP(email_cfg["smtp_host"], email_cfg["smtp_port"]) as server:
            if email_cfg.get("smtp_user") and email_cfg.get("smtp_pass"):
                server.starttls()
                server.login(email_cfg["smtp_user"], email_cfg["smtp_pass"])
            server.sendmail(sender, [email_cfg["to"]], msg.as_string())
        print(f"[EMAIL SENT] {subject}")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}", file=sys.stderr)
        return False
