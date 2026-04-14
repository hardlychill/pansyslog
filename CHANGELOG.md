# Changelog

## 2026-04-13 — Dashboard, Baseline Protection, and Settings

### New Features

- **Web dashboard** — New `pansyslog-dashboard` container on port 8080 with full management UI:
  - **Dashboard** — System health, API key status, check stats, failing/suppressed DGs
  - **Active Alerts** — Acknowledge per-alert, per-DG, or all with one click
  - **Alert History** — Searchable/filterable by type, device group, admin. CSV export.
  - **Device Groups** — Rule counts (pre/post), baseline status per DG
  - **Baselines** — Browse rules per DG, highlight dangerous rules (no security profile, allow action). Reset per-DG or all with immediate re-check.
  - **Check History** — Timeline of checks with alert counts, manual trigger button
  - **Troubleshooting** — API key status, force re-auth, manual check, quick reference commands
  - **Settings** — Runtime-configurable settings with audit logging (see below)

- **Runtime settings via dashboard** — Email recipients, re-notification interval, debounce window, and parallel workers can be changed from the Settings page without restarting. All changes are logged to `/data/logs/config_changes.json` with timestamps. Panorama credentials, alert zones, and SMTP server settings remain file-only.

- **Baseline protection (BASELINE_ANOMALY)** — When the Panorama API returns 0 rules for a device group that previously had a populated baseline, pansyslog refuses to overwrite the baseline and fires a `BASELINE_ANOMALY` alert. Prevents data loss from transient API errors.

- **First-run summary** — On initial baseline creation, logs a breakdown of empty vs populated rulebases (pre/post) so the admin can verify which DGs are legitimately empty.

- **Check history persistence** — Check results (timestamp, DG count, alert count, per-DG summary) saved to `/data/logs/check_history.json` (last 100 entries). Viewable from the dashboard.

- **Separate email routing for system vs firewall alerts** — Firewall rule change alerts go to `email.to` (on-call). System alerts (baseline anomalies) go to `email.system_to` (admin/engineering). If `system_to` is empty, system alerts are logged but not emailed. On-call never gets spammed with system noise.

### New API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/settings` | GET | Current mutable settings |
| `/settings` | POST | Update settings at runtime |
| `/config-changes` | GET | Audit log of settings changes |
| `/check-history` | GET | Recent check results |
| `/alerts` | GET | Full alert history |
| `/baselines` | GET | All baselines with rule counts |
| `/baseline/reset` | POST | Reset per-DG or all baselines |
| `/reauth` | POST | Force API key refresh |

### Config Changes

New field in `config.yaml`:

```yaml
email:
  system_to: ""   # system alert recipient (empty = don't email system alerts)
```

### Data Changes

New files in `/data/logs/`:
- `check_history.json` — JSONL, last 100 check results
- `config_changes.json` — JSONL, audit log of runtime settings changes

### Docker Changes

New container in `docker-compose.yml`:

```yaml
dashboard:
  build: ./dashboard
  ports:
    - "8080:8080"
  volumes:
    - pansyslog-data:/data:ro
  environment:
    - PANSYSLOG_API=http://pansyslog:8787
```

Vector GraphQL port (8686) removed from compose — was unnecessary exposure.

### Upgrade Instructions

```bash
git pull
docker compose up -d --build
```

Dashboard is available at `http://<docker-host>:8080`. No config changes required — new fields have safe defaults.

---

## 2026-04-10 — Alert Classification Improvements

### New Features

- **CRITICAL_SEGMENTATION_REMOTE_ACCESS alert type** — Rules that break zone segmentation AND allow remote access now fire a dedicated critical alert instead of reporting only one condition. Alert details include both the zone violation and the specific remote-access trigger.

- **FILE_SHARING_RULE alert type** — New alert for rules that allow file-sharing applications. Uses PAN-OS `file-sharing` subcategory (same approach as remote-access detection). Fires on rules with explicit file-sharing apps or `app=any`. Also has a critical combined variant (`CRITICAL_SEGMENTATION_FILE_SHARING`) when paired with a zone break.

- **Combined alert context** — `should_alert` now evaluates all criteria (zone, remote-access, file-sharing) for every rule instead of short-circuiting on the first match. Alerts include full context of all violations.

### Alert Type Hierarchy

| Type | Severity | Condition |
|------|----------|-----------|
| `CRITICAL_SEGMENTATION_REMOTE_ACCESS` | Critical | Zone break + remote access |
| `CRITICAL_SEGMENTATION_FILE_SHARING` | Critical | Zone break + file sharing |
| `BREAK_OF_SEGMENTATION` | High | Zone pair violation only |
| `REMOTE_ACCESS_RULE` | Medium | Remote access (any zone) |
| `FILE_SHARING_RULE` | Medium | File sharing (any zone) |

Deny/drop rules never alert regardless of apps or zones.

### Data Changes

- New cache file: `/data/baselines/file-sharing_apps.json` (auto-created, 24h TTL)

### Upgrade Instructions

```bash
git pull
docker compose up -d --build
```

No config changes required. File-sharing detection is enabled automatically.

---

## 2026-04-09 — Post-Production Test Patch

Changes made after initial production deployment and testing against live Panorama environment.

### Bug Fixes

- **Credential leak in error logs** — API errors from `requests` library included the full URL with API key and password. All error messages are now redacted to exclude sensitive URL parameters.

- **Templates enumerated as device groups** — Device group enumeration returned templates and template-stacks alongside real DGs, causing 403 errors on template entries. Now cross-references against Panorama's template and template-stack lists and excludes them.

- **API session buildup on Panorama** — Each check cycle created a new `PanoramaClient` and called keygen, opening a new session. Panorama's concurrent session limit caused 403 denials. Now creates one API session at startup and reuses it for the process lifetime.

- **Wrong admin attribution on alerts** — When multiple admins committed between check cycles, all alerts were attributed to the most recent committer only. Now lists all unique committers from the config log.

- **Baseline not saved on alert failure** — If `log_alert` threw an exception (e.g., disk full), the baseline wasn't updated, causing the same rules to re-alert on every subsequent check. Baseline save now runs in a `finally` block.

### New Features

- **API key auto-renewal** — If Panorama invalidates the API key (password change, reboot, session timeout), pansyslog detects the 403 and re-authenticates automatically without requiring a container restart.

- **Parallel device group checks** — Device groups are now checked concurrently using a thread pool (default 10 workers, configurable via `max_workers` in config.yaml). Reduces check cycle time ~10x for large environments.

- **Failure suppression** — Device groups that fail 3 consecutive times have their warnings suppressed to reduce log noise. Recovery is logged when they start responding again. Suppressed DGs are listed on the `/health` endpoint.

- **Unacknowledged alert tracking (disabled by default)** — When enabled (`renotify_hours > 0`), new alerts are tracked as "active" until explicitly acknowledged. Unacknowledged alerts trigger a reminder email at the configured interval. Alerts auto-resolve when the offending rule is removed. Disabled by default to avoid noise until an acknowledgment workflow is in place. All related endpoints return `{"status": "disabled"}` when off.

- **Management API endpoints:**
  - `GET /health` — Status, uptime, API key state, check stats, failing/suppressed DGs, unacknowledged alert count (or "disabled")
  - `GET /active-alerts` — List all unacknowledged alerts with first-seen time and notification count (returns "disabled" when `renotify_hours: 0`)
  - `POST /check` — Manual check trigger that bypasses debounce (for testing and post-deploy verification)
  - `POST /acknowledge` — Acknowledge specific alerts or all alerts to stop re-notifications (returns "disabled" when `renotify_hours: 0`)

- **Config log depth increased** — Pulls 50 recent config log entries (up from 10) to better capture all committers in busy environments.

- **Unauthenticated SMTP relay support** — STARTTLS and login are skipped when `smtp_user` and `smtp_pass` are empty, allowing use with internal mail forwarders that don't require authentication.

### Config Changes

New fields in `config.yaml` (all optional with defaults):

```yaml
max_workers: 10    # parallel device group checks (default: 10)
renotify_hours: 0  # re-email unacknowledged alerts every N hours (default: 0 = disabled)
                   # set to 24 to enable daily re-notification reminders
```

### Upgrade Instructions

```bash
git pull
docker compose up -d --build
```

No data migration needed. Existing baselines and alert logs are compatible. The new `active_alerts.json` tracker file is created automatically on first alert.
