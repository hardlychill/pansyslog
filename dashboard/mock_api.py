"""Mock pansyslog API for local dashboard testing."""

import json
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

DATA_DIR = Path("/Users/bonk/pansyslog/data")
START_TIME = datetime.now()
CHECK_COUNT = 4
ALERT_COUNT = 6

MOCK_SETTINGS = {
    "email_to": "oncall@example.com",
    "email_system_to": "admin@example.com",
    "renotify_hours": 24,
    "debounce_seconds": 30,
    "max_workers": 10,
}
CONFIG_CHANGES = []

ACTIVE_ALERTS = {
    "DG-datacenter|allow-rdp-wan-to-trust|CRITICAL_SEGMENTATION_REMOTE_ACCESS_ADDED": {
        "device_group": "DG-datacenter",
        "rule_name": "allow-rdp-wan-to-trust",
        "alert_type": "CRITICAL_SEGMENTATION_REMOTE_ACCESS_ADDED",
        "details": "Rule allows RDP from untrust-WAN to trust-SERVERS — zone break + remote access",
        "first_seen": "2026-04-13T09:15:22",
        "last_notified": "2026-04-13T09:15:22",
        "notify_count": 3,
    },
    "DG-branch-offices|temp-allow-all|BREAK_OF_SEGMENTATION_ADDED": {
        "device_group": "DG-branch-offices",
        "rule_name": "temp-allow-all",
        "alert_type": "BREAK_OF_SEGMENTATION_ADDED",
        "details": "Rule allows any/any from untrust-MPLS to trust-LAN — zone break",
        "first_seen": "2026-04-13T08:42:10",
        "last_notified": "2026-04-13T08:42:10",
        "notify_count": 1,
    },
    "DG-dmz|vnc-access|REMOTE_ACCESS_RULE_ADDED": {
        "device_group": "DG-dmz",
        "rule_name": "vnc-access",
        "alert_type": "REMOTE_ACCESS_RULE_ADDED",
        "details": "Rule allows VNC between DMZ zones — remote access app detected",
        "first_seen": "2026-04-12T14:22:05",
        "last_notified": "2026-04-12T14:22:05",
        "notify_count": 2,
    },
    "DG-datacenter|allow-ftp-outbound|FILE_SHARING_RULE_ADDED": {
        "device_group": "DG-datacenter",
        "rule_name": "allow-ftp-outbound",
        "alert_type": "FILE_SHARING_RULE_ADDED",
        "details": "Rule allows FTP outbound from trust-SERVERS — file sharing app detected",
        "first_seen": "2026-04-12T11:05:33",
        "last_notified": "2026-04-12T11:05:33",
        "notify_count": 1,
    },
    "DG-remote-sites|smb-share-access|CRITICAL_SEGMENTATION_FILE_SHARING_ADDED": {
        "device_group": "DG-remote-sites",
        "rule_name": "smb-share-access",
        "alert_type": "CRITICAL_SEGMENTATION_FILE_SHARING_ADDED",
        "details": "Rule allows SMB from untrust-REMOTE to trust-FILESVR — zone break + file sharing",
        "first_seen": "2026-04-11T16:30:00",
        "last_notified": "2026-04-12T16:30:00",
        "notify_count": 2,
    },
}


class MockHandler(BaseHTTPRequestHandler):
    def _json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.rstrip("/")

        if path == "/health":
            self._json(200, {
                "status": "ok",
                "uptime_seconds": int((datetime.now() - START_TIME).total_seconds()),
                "panorama": "10.0.0.1",
                "api_key_valid": True,
                "api_key_obtained": START_TIME.isoformat(),
                "total_checks": CHECK_COUNT,
                "total_alerts": ALERT_COUNT,
                "last_check": "2026-04-13T09:15:00",
                "last_check_alerts": 1,
                "alert_log_entries": 6,
                "dg_failing": ["BRSFW_Unified/pre"],
                "dg_suppressed": ["LEGACY-template/pre", "LEGACY-template/post"],
                "debounce_seconds": 30,
                "email_enabled": True,
                "unacknowledged_alerts": len(ACTIVE_ALERTS),
                "renotify_hours": 24,
            })

        elif path == "/active-alerts":
            self._json(200, ACTIVE_ALERTS)

        elif path == "/check-history":
            history_file = DATA_DIR / "logs" / "check_history.json"
            entries = []
            if history_file.exists():
                with open(history_file) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            entries.append(json.loads(line))
            self._json(200, entries)

        elif path == "/alerts":
            alert_file = DATA_DIR / "logs" / "alerts.json"
            entries = []
            if alert_file.exists():
                with open(alert_file) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            entries.append(json.loads(line))
            self._json(200, entries)

        elif path == "/baselines":
            baseline_dir = DATA_DIR / "baselines"
            baselines = {}
            for f in sorted(baseline_dir.glob("*_baseline.json")):
                with open(f) as fh:
                    rules = json.load(fh)
                baselines[f.stem] = {
                    "file": f.name,
                    "rule_count": len(rules),
                    "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                }
            self._json(200, baselines)

        elif path == "/settings":
            self._json(200, MOCK_SETTINGS)

        elif path == "/config-changes":
            self._json(200, CONFIG_CHANGES)

        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.rstrip("/")
        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length)

        if path == "/check":
            self._json(200, {"status": "check triggered"})

        elif path == "/acknowledge":
            try:
                body = json.loads(raw.decode()) if raw else {}
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid JSON"})
                return

            if body.get("all"):
                count = len(ACTIVE_ALERTS)
                ACTIVE_ALERTS.clear()
                self._json(200, {"acknowledged": count})
            else:
                dg = body.get("device_group", "")
                rule = body.get("rule_name", "")
                to_remove = [
                    k for k, v in ACTIVE_ALERTS.items()
                    if v["device_group"] == dg and v["rule_name"] == rule
                ]
                for k in to_remove:
                    del ACTIVE_ALERTS[k]
                self._json(200, {"acknowledged": len(to_remove) > 0})

        elif path == "/baseline/reset":
            try:
                body = json.loads(raw.decode()) if raw else {}
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid JSON"})
                return
            self._json(200, {"reset": [], "count": 0, "note": "mock — no files deleted"})

        elif path == "/reauth":
            self._json(200, {"status": "ok", "api_key_obtained": datetime.now().isoformat()})

        elif path == "/settings":
            try:
                body = json.loads(raw.decode()) if raw else {}
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid JSON"})
                return
            changes = []
            for key, value in body.items():
                if key in MOCK_SETTINGS:
                    old = MOCK_SETTINGS[key]
                    if old != value:
                        MOCK_SETTINGS[key] = value
                        changes.append({"setting": key, "old_value": old, "new_value": value})
            if changes:
                CONFIG_CHANGES.append({"timestamp": datetime.now().isoformat(), "changes": changes})
            self._json(200, {"updated": changes})

        else:
            self._json(404, {"error": "not found"})

    def log_message(self, format, *args):
        pass


def run():
    server = HTTPServer(("127.0.0.1", 8787), MockHandler)
    print("[mock] pansyslog mock API running on :8787")
    server.serve_forever()


if __name__ == "__main__":
    run()
