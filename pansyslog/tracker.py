"""Unacknowledged alert tracker — persists active alerts and re-notifies."""

import json
import threading
from datetime import datetime
from pathlib import Path


class AlertTracker:
    """Tracks unacknowledged alerts and supports re-notification.

    Active alerts are keyed by (device_group, rule_name, alert_type).
    An alert stays active until explicitly acknowledged via the API.
    Re-notification fires after renotify_hours if still unacknowledged.
    """

    def __init__(self, data_dir, renotify_hours=24):
        self.data_dir = Path(data_dir)
        self.active_file = self.data_dir / "logs" / "active_alerts.json"
        self.renotify_hours = renotify_hours
        self._lock = threading.Lock()
        self._active = self._load()

    def _load(self):
        """Load active alerts from disk."""
        if self.active_file.exists():
            try:
                with open(self.active_file) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _save(self):
        """Persist active alerts to disk."""
        self.active_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.active_file, "w") as f:
            json.dump(self._active, f, indent=2)

    @staticmethod
    def _key(device_group, rule_name, alert_type):
        return f"{device_group}|{rule_name}|{alert_type}"

    def record(self, device_group, rule_name, alert_type, details=""):
        """Record a new alert as active/unacknowledged."""
        key = self._key(device_group, rule_name, alert_type)
        now = datetime.now().isoformat()
        with self._lock:
            if key not in self._active:
                self._active[key] = {
                    "device_group": device_group,
                    "rule_name": rule_name,
                    "alert_type": alert_type,
                    "details": details,
                    "first_seen": now,
                    "last_notified": now,
                    "notify_count": 1,
                }
            else:
                # Already tracked — don't reset, just note it was seen again
                self._active[key]["details"] = details
            self._save()

    def acknowledge(self, device_group=None, rule_name=None, alert_type=None, key=None):
        """Acknowledge an alert to stop re-notifications. Returns True if found."""
        with self._lock:
            if key and key in self._active:
                del self._active[key]
                self._save()
                return True
            if device_group and rule_name:
                # Match by DG + rule name (any alert type)
                to_remove = [
                    k for k in self._active
                    if self._active[k]["device_group"] == device_group
                    and self._active[k]["rule_name"] == rule_name
                    and (alert_type is None or self._active[k]["alert_type"] == alert_type)
                ]
                for k in to_remove:
                    del self._active[k]
                if to_remove:
                    self._save()
                    return True
            return False

    def acknowledge_all(self):
        """Acknowledge all active alerts. Returns count cleared."""
        with self._lock:
            count = len(self._active)
            self._active.clear()
            self._save()
            return count

    def get_due_renotifications(self):
        """Return alerts that are due for re-notification."""
        now = datetime.now()
        due = []
        with self._lock:
            for key, alert in self._active.items():
                last = datetime.fromisoformat(alert["last_notified"])
                hours_since = (now - last).total_seconds() / 3600
                if hours_since >= self.renotify_hours:
                    due.append((key, alert))
            # Update last_notified for due alerts
            for key, _ in due:
                self._active[key]["last_notified"] = now.isoformat()
                self._active[key]["notify_count"] += 1
            if due:
                self._save()
        return due

    def list_active(self):
        """Return all active (unacknowledged) alerts."""
        with self._lock:
            return dict(self._active)

    def remove_resolved(self, current_rule_names_by_dg):
        """Remove alerts for rules that no longer exist in the rulebase.

        current_rule_names_by_dg: {device_group: set(rule_names)}
        """
        with self._lock:
            to_remove = []
            for key, alert in self._active.items():
                dg = alert["device_group"]
                rule = alert["rule_name"]
                if dg in current_rule_names_by_dg:
                    if rule not in current_rule_names_by_dg[dg]:
                        to_remove.append(key)
            for k in to_remove:
                print(f"[TRACKER] Auto-resolved: {self._active[k]['rule_name']} "
                      f"in {self._active[k]['device_group']} (rule no longer exists)")
                del self._active[k]
            if to_remove:
                self._save()
            return len(to_remove)
