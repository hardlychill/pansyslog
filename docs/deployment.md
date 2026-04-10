# pansyslog Deployment Guide

Instructions for building, deploying, and operating pansyslog in production.

## Overview

pansyslog is a Docker Compose stack with two containers:
- **pansyslog** — Python webhook server that monitors Panorama for insecure rule changes
- **vector** — Syslog receiver that filters and forwards config-change events

## Requirements

- Docker and Docker Compose (v2)
- Network access from the deployment host to Panorama on HTTPS (443)
- Network access from Panorama to the deployment host on UDP 5514
- SMTP relay or Gmail app password for email alerts
- Panorama admin account with XML API read access (see [panorama-syslog-setup.md](panorama-syslog-setup.md))

**Important: The Panorama API user must not have concurrent session limits.** pansyslog maintains a single persistent API session. If sessions get stuck, clear them from Panorama > Administrators before restarting.

## Build and Deploy

### 1. Clone the repo

```bash
git clone https://github.com/hardlychill/pansyslog.git
cd pansyslog
```

### 2. Configure

Edit `config.yaml`:

```yaml
panorama:
  host: 10.0.0.1           # Panorama management IP
  user: pansyslog-api       # API user (see panorama-syslog-setup.md)
  password: changeme        # Override via PAN_PASS env var
  device_groups: all        # Auto-enumerate, or list specific DGs

alert_zones:
  - [untrust-, trust-]      # Prefix match: untrust-* <-> trust-*

email:
  enabled: true
  to: security-alerts@yourorg.com
  smtp_host: mail-relay.internal  # Internal relay (no auth needed)
  smtp_port: 25

debounce_seconds: 30
max_workers: 10             # Parallel device group checks
renotify_hours: 24          # Re-email unacknowledged alerts (0 to disable)
```

**Internal mail relay:** If your SMTP relay doesn't require authentication, leave `smtp_user` and `smtp_pass` empty. pansyslog skips TLS/login when no credentials are set.

**Gmail:** Set `smtp_host: smtp.gmail.com`, `smtp_port: 587`, and provide `smtp_user`/`smtp_pass` via env vars.

### 3. Create .env for secrets

```bash
cat > .env << 'EOF'
PAN_PASS=your-panorama-password
SMTP_USER=
SMTP_PASS=
EOF
chmod 600 .env
```

Docker Compose reads `.env` automatically. Never commit this file (it's in `.gitignore`).

For internal relays with no auth, `SMTP_USER` and `SMTP_PASS` can be left empty.

### 4. Build and start

```bash
docker compose up -d --build
```

### 5. Verify

```bash
# Both containers running
docker compose ps

# pansyslog started cleanly
docker logs pansyslog
```

Expected output:
```
[pansyslog] API key obtained for 10.0.0.1
[pansyslog] Webhook server starting on port 8787
[pansyslog] Panorama: 10.0.0.1
[pansyslog] Device groups: all (auto-enumerate)
[pansyslog] Endpoints: POST / (webhook), POST /check (manual), POST /acknowledge, GET /health, GET /active-alerts
[pansyslog] Re-notification enabled: every 24h for unacknowledged alerts
[pansyslog] Alerts will be sent to security-alerts@yourorg.com
```

### 6. Configure Panorama syslog

Follow [panorama-syslog-setup.md](panorama-syslog-setup.md) to point Panorama config logs at `<deployment-host>:5514 UDP`.

### 7. Initialize baselines

The first check creates baselines for all device groups without alerting. You can trigger this immediately without waiting for a syslog event:

```bash
curl -X POST http://localhost:8787/check
```

Verify baselines were created:
```bash
docker exec pansyslog ls /data/baselines/
```

You should see `<DG-name>_pre_baseline.json` and `<DG-name>_post_baseline.json` for each device group.

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | POST | Webhook receiver (Vector sends here) |
| `/check` | POST | Manual check trigger (bypasses debounce) |
| `/health` | GET | Status, uptime, API key, stats, failing DGs |
| `/active-alerts` | GET | List all unacknowledged alerts |
| `/acknowledge` | POST | Acknowledge alerts to stop re-notifications |

### Health check

```bash
curl http://localhost:8787/health
```

Returns JSON with: status, uptime, API key state, total checks/alerts, last check time, failing/suppressed device groups, unacknowledged alert count.

### View unacknowledged alerts

```bash
curl http://localhost:8787/active-alerts
```

### Acknowledge alerts

```bash
# Acknowledge a specific rule in a device group
curl -X POST http://localhost:8787/acknowledge \
  -d '{"device_group":"DG-datacenter","rule_name":"bad-rule"}'

# Acknowledge all active alerts
curl -X POST http://localhost:8787/acknowledge -d '{"all":true}'
```

Unacknowledged alerts trigger a reminder email every `renotify_hours` (default 24h). Acknowledging stops the reminders. Alerts auto-resolve if the offending rule is removed from the rulebase.

## Operations

### View logs

```bash
# pansyslog application logs
docker logs -f pansyslog

# Config-change syslog events (filtered)
docker logs pansyslog-vector

# Alert history
docker exec pansyslog cat /data/logs/alerts.json | python3 -m json.tool
```

Note: Raw syslog is not written to disk — it's only available via `docker logs`. Docker rotates these at 10MB x 3 files per container (30MB max).

### View baselines

```bash
docker exec pansyslog ls /data/baselines/
docker exec pansyslog cat /data/baselines/DG-datacenter_pre_baseline.json | python3 -m json.tool
```

### Reset baselines

After a planned mass change, reset baselines to prevent a flood of alerts:

```bash
# Reset all baselines
docker exec pansyslog sh -c 'rm /data/baselines/*_baseline.json'

# Reset one device group
docker exec pansyslog rm /data/baselines/DG-datacenter_pre_baseline.json
docker exec pansyslog rm /data/baselines/DG-datacenter_post_baseline.json

# Trigger a re-baseline
curl -X POST http://localhost:8787/check
```

### Update after code changes

```bash
git pull
docker compose up -d --build
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PAN_HOST` | Panorama IP/hostname | from config.yaml |
| `PAN_USER` | API username | `admin` |
| `PAN_PASS` | API password | from config.yaml |
| `SMTP_USER` | Email sender (leave empty for unauthenticated relay) | (none) |
| `SMTP_PASS` | Email password | (none) |
| `EMAIL_TO` | Alert recipient | from config.yaml |
| `SMTP_HOST` | SMTP server | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | `587` |
| `WEBHOOK_PORT` | Webhook listen port | `8787` |
| `DEBOUNCE_SECONDS` | Debounce window | `30` |
| `DATA_DIR` | Data directory | `/data` |
| `PANSYSLOG_CONFIG` | Config file path | `/etc/pansyslog/config.yaml` |

## Data Persistence

The Docker volume `pansyslog-data` stores baselines, alert logs, active alert tracker, and caches. It persists across container restarts and rebuilds.

```
/data/
├── baselines/
│   ├── <DG>_pre_baseline.json
│   ├── <DG>_post_baseline.json
│   └── remote_access_apps.json    # 24h cache
└── logs/
    ├── alerts.json                # Alert history (JSONL, capped at 1000)
    └── active_alerts.json         # Unacknowledged alert tracker
```

To back up:
```bash
docker run --rm -v pansyslog-data:/data -v $(pwd):/backup alpine tar czf /backup/pansyslog-data.tar.gz /data
```

## Architecture Notes

### API session management
pansyslog creates **one** Panorama API session at startup and reuses it for all checks. If the API key expires or is invalidated (password change, Panorama reboot), pansyslog auto-detects the 403 and re-authenticates. No manual restart required.

### Device group enumeration
With `device_groups: all`, pansyslog queries Panorama for all device groups and cross-references against the template and template-stack lists to exclude non-DG entries. This runs on every check cycle.

### Parallel checks
Device groups are checked in parallel using a thread pool (default 10 workers, configurable via `max_workers`). All workers share the same API key.

### Debounce
The webhook uses a trailing-edge debounce. Multiple syslog events within 30 seconds coalesce into one check. Events during the debounce window are not dropped — a deferred check runs when the window expires.

### Failure suppression
If a device group fails 3 consecutive times, warnings are suppressed to reduce log noise. When it recovers, a `[RECOVERED]` message is logged. The `/health` endpoint lists suppressed DGs.

### Credential safety
API keys and passwords are never logged. Error messages from the Panorama API are redacted to exclude URL parameters.

## Troubleshooting

**403 "authentication failed" on startup:**
- Verify credentials in config.yaml / .env
- Check that the Panorama admin account has XML API permissions (Configuration read, Log read)
- Clear any stale sessions: Panorama > Administrators > select user > clear sessions

**Templates appearing as device groups:**
- pansyslog excludes templates by cross-referencing. If new templates still appear, check `docker logs pansyslog` for the enumeration output and report the template name.

**Alerts attribute wrong admin:**
- When multiple admins commit between check cycles, the alert lists all recent committers. This is by design — Panorama's config log doesn't tie individual rule changes to specific commits.

**Check cycle is slow:**
- Increase `max_workers` in config.yaml to allow more parallel DG checks
- Or scope `device_groups` to only the DGs you care about

**Repeated alerts for the same rule:**
- Should not happen — baselines update via try/finally even if alerting fails
- If it does, check disk space (`docker exec pansyslog df -h /data`) — full disk prevents baseline writes
