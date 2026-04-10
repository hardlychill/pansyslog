# Changelog

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

- **Unacknowledged alert tracking** — New alerts are tracked as "active" until explicitly acknowledged. Unacknowledged alerts trigger a reminder email every 24 hours (configurable via `renotify_hours`). Alerts auto-resolve when the offending rule is removed.

- **Management API endpoints:**
  - `GET /health` — Status, uptime, API key state, check stats, failing/suppressed DGs, unacknowledged alert count
  - `GET /active-alerts` — List all unacknowledged alerts with first-seen time and notification count
  - `POST /check` — Manual check trigger that bypasses debounce (for testing and post-deploy verification)
  - `POST /acknowledge` — Acknowledge specific alerts or all alerts to stop re-notifications

- **Config log depth increased** — Pulls 50 recent config log entries (up from 10) to better capture all committers in busy environments.

- **Unauthenticated SMTP relay support** — STARTTLS and login are skipped when `smtp_user` and `smtp_pass` are empty, allowing use with internal mail forwarders that don't require authentication.

### Config Changes

New fields in `config.yaml` (all optional with defaults):

```yaml
max_workers: 10    # parallel device group checks (default: 10)
renotify_hours: 24 # re-email unacknowledged alerts every N hours (default: 24, 0 to disable)
```

### Upgrade Instructions

```bash
git pull
docker compose up -d --build
```

No data migration needed. Existing baselines and alert logs are compatible. The new `active_alerts.json` tracker file is created automatically on first alert.
