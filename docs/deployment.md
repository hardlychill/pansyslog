# pansyslog Deployment Guide

Instructions for building, deploying, and running pansyslog in production.

## Overview

pansyslog is a Docker Compose stack with two containers:
- **pansyslog** — Python webhook server that checks Panorama rules on syslog events
- **vector** — Syslog receiver that filters and forwards config-change events

## Requirements

- Docker and Docker Compose (v2)
- Network access from the deployment host to Panorama on HTTPS (443)
- Network access from Panorama to the deployment host on UDP 5514
- Gmail app password (or other SMTP credentials) for email alerts

## Build and Deploy

### 1. Clone the repo

```bash
git clone <repo-url> pansyslog
cd pansyslog
```

### 2. Configure

Edit `config.yaml`:

```yaml
panorama:
  host: 10.0.0.1           # Panorama management IP
  user: pansyslog-api       # API user (see panorama-syslog-setup.md)
  password: changeme        # Override via PAN_PASS env var

  device_groups: all        # Or list specific DGs:
  # device_groups:
  #   - DG-datacenter
  #   - DG-branch-offices

alert_zones:
  - [untrust-, trust-]      # Prefix match: untrust-* <-> trust-*

email:
  enabled: true
  to: security-alerts@yourorg.com
```

### 3. Create .env for secrets

```bash
cat > .env << 'EOF'
PAN_PASS=your-panorama-password
SMTP_USER=alerting@gmail.com
SMTP_PASS=xxxx xxxx xxxx xxxx
EOF
chmod 600 .env
```

Docker Compose reads `.env` automatically. Never commit this file (it's in `.gitignore`).

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

# Vector listening for syslog
docker logs pansyslog-vector
```

Expected pansyslog output:
```
[pansyslog] Webhook server starting on port 8787
[pansyslog] Panorama: 10.0.0.1
[pansyslog] Device groups: all (auto-enumerate)
[pansyslog] Alerts will be sent to security-alerts@yourorg.com
```

### 6. Configure Panorama syslog

Follow [panorama-syslog-setup.md](panorama-syslog-setup.md) to point Panorama config logs at `<deployment-host>:5514`.

### 7. Initialize baselines

The first syslog event after deployment will trigger a full baseline capture across all device groups. No alerts fire on this first run — it records the current state. Alerts begin on the next committed change.

To force an immediate baseline without waiting for a syslog event:

```bash
docker exec pansyslog python -c "
from pansyslog.config import load_config
from pansyslog.check import run_check
run_check(load_config())
"
```

## Operations

### View logs

```bash
# pansyslog application logs
docker logs -f pansyslog

# Raw syslog from Panorama
docker exec pansyslog-vector cat /data/logs/all_syslog.log | tail -20

# Alert history
docker exec pansyslog cat /data/logs/alerts.json | python3 -m json.tool --no-ensure-ascii
```

### View baselines

```bash
# List all baselines
docker exec pansyslog ls /data/baselines/

# View a specific DG baseline
docker exec pansyslog cat /data/baselines/DG-datacenter_pre_baseline.json | python3 -m json.tool
```

### Reset baselines

To re-baseline (e.g., after a planned mass change):

```bash
# Reset all baselines
docker exec pansyslog rm /data/baselines/*_baseline.json

# Reset one device group
docker exec pansyslog rm /data/baselines/DG-datacenter_pre_baseline.json
docker exec pansyslog rm /data/baselines/DG-datacenter_post_baseline.json
```

Next syslog event will re-capture baselines without alerting.

### Restart after config change

```bash
docker compose down
docker compose up -d --build
```

### Update

```bash
git pull
docker compose up -d --build
```

## Environment Variables

All config values can be overridden via env vars (set in `.env` or `docker-compose.yml`):

| Variable | Description | Default |
|----------|-------------|---------|
| `PAN_HOST` | Panorama IP/hostname | from config.yaml |
| `PAN_USER` | API username | `admin` |
| `PAN_PASS` | API password | from config.yaml |
| `SMTP_USER` | Email sender address | (none) |
| `SMTP_PASS` | Email password/app password | (none) |
| `EMAIL_TO` | Alert recipient | from config.yaml |
| `SMTP_HOST` | SMTP server | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | `587` |
| `WEBHOOK_PORT` | Webhook listen port | `8787` |
| `DEBOUNCE_SECONDS` | Debounce window | `30` |
| `DATA_DIR` | Data directory | `/data` |
| `PANSYSLOG_CONFIG` | Config file path | `/etc/pansyslog/config.yaml` |

## Data Persistence

The Docker volume `pansyslog-data` stores baselines, logs, and caches. It persists across container restarts and rebuilds.

To back up:
```bash
docker run --rm -v pansyslog-data:/data -v $(pwd):/backup alpine tar czf /backup/pansyslog-data.tar.gz /data
```

## Panorama API Considerations

- **Device group enumeration** (`device_groups: all`) makes one API call at startup to list all DGs
- **Each check cycle** makes 2 API calls per device group (pre + post rulebase) plus shared resources
- With 70 device groups, expect ~145 API calls per check cycle
- The 30-second debounce prevents rapid repeated checks
- Remote-access app list is cached for 24 hours to avoid redundant calls
- Consider listing only the device groups you care about to reduce API load

## Known Limitations

- Panorama XML API xpaths may need adjustment depending on your PAN-OS version — verify against your environment
- The system checks all device groups on every syslog event (no per-DG routing from syslog content yet)
- Single-threaded API calls per check cycle — 70 DGs at ~2s each = ~2-3 min per check
- No retry on transient API failures (network blips during a check cycle skip that DG)

## Future Improvements

These are areas where the deploying agent may need to adapt the code to the production environment:

- **Panorama xpath validation** — xpaths for device-group rulebases may differ by PAN-OS version. Test `api.py` methods against your Panorama and adjust if needed.
- **Parallel DG checks** — swap sequential loop in `check.py` for `concurrent.futures.ThreadPoolExecutor` if check cycles are too slow
- **Syslog-to-DG routing** — parse the syslog message to identify which device group changed, check only that DG instead of all 70
- **Slack/webhook alerting** — add an alerter alongside email
- **Health check endpoint** — add a `/health` route to the webhook server for monitoring
