"""Webhook server — receives syslog events from Vector, runs checks, sends email alerts."""

import json
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

from .check import run_check
from .email_alert import send_email


class WebhookServer:
    """Webhook listener with trailing-edge debounce."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.data_dir = Path(cfg["data_dir"])
        self.alert_log = self.data_dir / "logs" / "alerts.json"
        self.debounce_seconds = cfg["debounce_seconds"]
        self._last_check = 0
        self._pending = False
        self._lock = threading.Lock()

    def _deferred_check(self, delay):
        """Wait for debounce window to expire, then run if still pending."""
        time.sleep(delay)
        with self._lock:
            if not self._pending:
                return
            self._pending = False
        self._do_check()

    def handle_event(self):
        """Called on each incoming syslog event from Vector."""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_check
            if elapsed < self.debounce_seconds:
                if not self._pending:
                    self._pending = True
                    remaining = self.debounce_seconds - elapsed
                    threading.Thread(
                        target=self._deferred_check, args=(remaining,), daemon=True
                    ).start()
                    print(f"[DEBOUNCE] Check deferred, will run in {int(remaining)}s")
                else:
                    print(f"[DEBOUNCE] Check already scheduled, skipping")
                return
            self._last_check = now

        self._do_check()

    def _do_check(self):
        """Run checks across all device groups and send email if alerts found."""
        # Snapshot alert log size
        alert_count_before = 0
        if self.alert_log.exists():
            with open(self.alert_log) as f:
                alert_count_before = sum(1 for _ in f)

        total_new = run_check(self.cfg)

        if total_new > 0:
            self._send_alert_email(alert_count_before, total_new)
        else:
            print("[OK] No new alerts from this change.")

    def _send_alert_email(self, alert_count_before, new_count):
        """Read new alert entries and send summary email."""
        if not self.alert_log.exists():
            return

        with open(self.alert_log) as f:
            lines = f.readlines()

        new_alerts = lines[-new_count:]
        alert_details = []
        for line in new_alerts:
            alert = json.loads(line.strip())
            alert_details.append(
                f"Type: {alert['alert_type']}\n"
                f"Device Group: {alert.get('device_group', 'unknown')}\n"
                f"Rule: {alert['rule_name']}\n"
                f"Changed by: {alert.get('changed_by', 'unknown')}\n"
                f"Client: {alert.get('client', 'unknown')}\n"
                f"Source IP: {alert.get('source_ip', 'unknown')}\n"
                f"Device: {alert.get('device_name', 'unknown')} (S/N: {alert.get('serial', 'unknown')})\n"
                f"Commit time: {alert.get('commit_time', 'unknown')}\n"
                f"Details: {alert['details']}\n"
                f"Alert time: {alert['timestamp']}"
            )

        host = self.cfg["panorama"]["host"]
        body = (
            f"pansyslog detected {new_count} insecure rule change(s) on Panorama ({host}):\n\n"
            + "\n---\n".join(alert_details)
        )
        send_email(
            self.cfg,
            f"[pansyslog] {new_count} insecure rule change(s) detected",
            body,
        )

    def serve(self):
        """Start the HTTP webhook listener."""
        port = self.cfg["webhook_port"]
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(content_length)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
                threading.Thread(target=server_ref.handle_event, daemon=True).start()

            def log_message(self, format, *args):
                pass

        pan_host = self.cfg["panorama"]["host"]
        dg_cfg = self.cfg["panorama"]["device_groups"]
        dg_label = "all (auto-enumerate)" if dg_cfg == "all" else f"{len(dg_cfg)} configured"

        print(f"[pansyslog] Webhook server starting on port {port}")
        print(f"[pansyslog] Panorama: {pan_host}")
        print(f"[pansyslog] Device groups: {dg_label}")
        if self.cfg["email"]["enabled"]:
            print(f"[pansyslog] Alerts will be sent to {self.cfg['email']['to']}")
        else:
            print("[pansyslog] WARNING: Email not configured - alerts will be logged only")

        httpd = HTTPServer(("0.0.0.0", port), Handler)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[pansyslog] Shutting down.")
            httpd.server_close()
