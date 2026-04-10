"""Webhook server — receives syslog events from Vector, runs checks, sends email alerts."""

import json
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

from .api import PanoramaClient
from .check import run_check, _dg_failures
from .email_alert import send_email
from .tracker import AlertTracker


class WebhookServer:
    """Webhook listener with trailing-edge debounce, health and manual trigger endpoints."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.data_dir = Path(cfg["data_dir"])
        self.alert_log = self.data_dir / "logs" / "alerts.json"
        self.debounce_seconds = cfg["debounce_seconds"]
        self._last_check = 0
        self._last_check_time = None
        self._last_check_alerts = 0
        self._total_checks = 0
        self._total_alerts = 0
        self._check_running = False
        self._pending = False
        self._lock = threading.Lock()
        self._start_time = datetime.now()

        # Single persistent API client — one keygen for the process lifetime
        pan_cfg = cfg["panorama"]
        self.client = PanoramaClient(
            pan_cfg["host"], pan_cfg["user"], pan_cfg["password"],
            data_dir=cfg["data_dir"],
        )

        # Unacknowledged alert tracker
        renotify_hours = cfg.get("renotify_hours", 24)
        self.tracker = AlertTracker(cfg["data_dir"], renotify_hours=renotify_hours)

        # Start re-notification background thread
        if renotify_hours > 0:
            self._start_renotify_loop(renotify_hours)

    def _start_renotify_loop(self, interval_hours):
        """Background thread that checks for due re-notifications."""
        def _loop():
            # Check every hour
            while True:
                time.sleep(3600)
                due = self.tracker.get_due_renotifications()
                if due:
                    print(f"[RENOTIFY] {len(due)} unacknowledged alert(s) due for re-notification")
                    details = []
                    for key, alert in due:
                        details.append(
                            f"Type: {alert['alert_type']}\n"
                            f"Device Group: {alert['device_group']}\n"
                            f"Rule: {alert['rule_name']}\n"
                            f"First seen: {alert['first_seen']}\n"
                            f"Notification #: {alert['notify_count']}\n"
                            f"Details: {alert['details']}"
                        )
                    host = self.cfg["panorama"]["host"]
                    body = (
                        f"pansyslog REMINDER: {len(due)} unacknowledged insecure rule(s) "
                        f"on Panorama ({host}):\n\n"
                        + "\n---\n".join(details)
                        + f"\n\nAcknowledge via: POST http://<pansyslog>:8787/acknowledge"
                    )
                    send_email(
                        self.cfg,
                        f"[pansyslog] REMINDER: {len(due)} unacknowledged alert(s)",
                        body,
                    )

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        print(f"[pansyslog] Re-notification enabled: every {interval_hours}h for unacknowledged alerts")

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
        self._check_running = True

        # Snapshot alert log size
        alert_count_before = 0
        if self.alert_log.exists():
            with open(self.alert_log) as f:
                alert_count_before = sum(1 for _ in f)

        total_new = run_check(self.cfg, client=self.client, tracker=self.tracker)

        self._total_checks += 1
        self._total_alerts += total_new
        self._last_check_time = datetime.now()
        self._last_check_alerts = total_new
        self._check_running = False

        if total_new > 0:
            self._send_alert_email(alert_count_before, total_new)
        else:
            print("[OK] No new alerts from this change.")

        self._rotate_alert_log()

    def _rotate_alert_log(self, max_entries=1000):
        """Trim alert log to the most recent max_entries lines."""
        if not self.alert_log.exists():
            return
        with open(self.alert_log) as f:
            lines = f.readlines()
        if len(lines) <= max_entries:
            return
        with open(self.alert_log, "w") as f:
            f.writelines(lines[-max_entries:])
        print(f"[ROTATE] Trimmed alerts.json from {len(lines)} to {max_entries} entries")

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

    def _get_health(self):
        """Build health status dict."""
        suppressed = [k for k, v in _dg_failures.items() if v >= 3]
        failing = [k for k, v in _dg_failures.items() if 0 < v < 3]

        alert_count = 0
        if self.alert_log.exists():
            with open(self.alert_log) as f:
                alert_count = sum(1 for _ in f)

        return {
            "status": "ok" if not self._check_running else "checking",
            "uptime_seconds": int((datetime.now() - self._start_time).total_seconds()),
            "panorama": self.cfg["panorama"]["host"],
            "api_key_valid": self.client._api_key is not None,
            "api_key_obtained": self.client._key_time.isoformat() if self.client._key_time else None,
            "total_checks": self._total_checks,
            "total_alerts": self._total_alerts,
            "last_check": self._last_check_time.isoformat() if self._last_check_time else None,
            "last_check_alerts": self._last_check_alerts,
            "alert_log_entries": alert_count,
            "dg_failing": failing,
            "dg_suppressed": suppressed,
            "debounce_seconds": self.debounce_seconds,
            "email_enabled": self.cfg["email"]["enabled"],
            "unacknowledged_alerts": len(self.tracker.list_active()),
            "renotify_hours": self.cfg.get("renotify_hours", 24),
        }

    def serve(self):
        """Start the HTTP webhook listener."""
        port = self.cfg["webhook_port"]
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def _json_response(self, code, data):
                body = json.dumps(data, indent=2).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                path = self.path.rstrip("/")
                content_length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(content_length)

                if path == "/check":
                    self._json_response(200, {"status": "check triggered"})
                    print("[MANUAL] Check triggered via /check endpoint")
                    threading.Thread(target=server_ref._do_check, daemon=True).start()

                elif path == "/acknowledge":
                    try:
                        body = json.loads(raw.decode()) if raw else {}
                    except json.JSONDecodeError:
                        self._json_response(400, {"error": "invalid JSON"})
                        return

                    if body.get("all"):
                        count = server_ref.tracker.acknowledge_all()
                        print(f"[ACK] All {count} alerts acknowledged")
                        self._json_response(200, {"acknowledged": count})
                    else:
                        dg = body.get("device_group", "")
                        rule = body.get("rule_name", "")
                        key = body.get("key", "")
                        found = server_ref.tracker.acknowledge(
                            device_group=dg, rule_name=rule, key=key,
                        )
                        if found:
                            print(f"[ACK] Acknowledged: {key or f'{dg}/{rule}'}")
                            self._json_response(200, {"acknowledged": True})
                        else:
                            self._json_response(404, {"error": "alert not found"})

                else:
                    # Normal webhook from Vector
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")
                    threading.Thread(target=server_ref.handle_event, daemon=True).start()

            def do_GET(self):
                path = self.path.rstrip("/")

                if path == "/health":
                    self._json_response(200, server_ref._get_health())

                elif path == "/active-alerts":
                    self._json_response(200, server_ref.tracker.list_active())

                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"not found")

            def log_message(self, format, *args):
                pass

        pan_host = self.cfg["panorama"]["host"]
        dg_cfg = self.cfg["panorama"]["device_groups"]
        dg_label = "all (auto-enumerate)" if dg_cfg == "all" else f"{len(dg_cfg)} configured"

        print(f"[pansyslog] Webhook server starting on port {port}")
        print(f"[pansyslog] Panorama: {pan_host}")
        print(f"[pansyslog] Device groups: {dg_label}")
        print(f"[pansyslog] Endpoints: POST / (webhook), POST /check (manual), "
              f"POST /acknowledge, GET /health, GET /active-alerts")
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
