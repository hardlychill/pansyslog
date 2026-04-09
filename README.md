# pansyslog

Panorama rule change monitoring and alerting. Detects insecure security rule changes across all device groups via syslog-triggered API diffs and sends email alerts.

## Architecture

```
+----------+    syslog (UDP 5514)    +--------+    HTTP POST    +-----------+
| Panorama | ----------------------> | Vector | --------------> | pansyslog |
+----------+                         +--------+                | webhook   |
                                          |                    +-----+-----+
                                          v                          |
                                   all_syslog.log          Panorama XML API
                                                           (per device group)
                                                                     |
                                                          +----------+----------+
                                                          |                     |
                                                     pre-rulebase         post-rulebase
                                                     (each DG)            (each DG)
                                                          |                     |
                                                          v                     v
                                                     Diff + Classify per DG
                                                              |
                                                              v
                                                        Email Alert
```

## Quick Start (Docker)

```bash
# Configure
vi config.yaml  # set panorama host, device groups, alert zones

# Run
PAN_PASS="panorama-password" SMTP_USER="you@gmail.com" SMTP_PASS="app-password" \
  docker compose up -d

# Point Panorama syslog to <docker-host>:5514 UDP
```

## Configuration

Edit `config.yaml`:

```yaml
panorama:
  host: 10.0.0.1
  user: admin
  password: changeme          # or use PAN_PASS env var

  device_groups: all          # auto-enumerate, or list specific ones:
  # device_groups:
  #   - DG-datacenter
  #   - DG-branch-offices

alert_zones:
  - [untrust-WAN, trust-GOOD]

email:
  enabled: true
  to: alerts@example.com
```

Env var overrides: `PAN_HOST`, `PAN_USER`, `PAN_PASS`, `SMTP_USER`, `SMTP_PASS`, `EMAIL_TO`, `WEBHOOK_PORT`, `DEBOUNCE_SECONDS`, `DATA_DIR`.

## Alert Types

**BREAK_OF_SEGMENTATION** — allow rule between configured zone pairs (e.g., untrust-WAN <-> trust-GOOD)

**REMOTE_ACCESS_RULE** — rule allowing remote-access traffic via:
- App matching PAN-OS `remote-access` subcategory (~197 apps)
- Port-based service objects resolving to known RA ports (RDP, SSH, VNC, etc.)
- Wide-open rules (app=any + service=any)

Deny/drop rules never alert.

## How It Works

1. Panorama sends syslog to Vector on UDP 5514
2. Vector filters for config-change keywords and POSTs to the webhook
3. Webhook (with trailing-edge debounce) triggers a check cycle
4. For each device group: pull pre-rulebase and post-rulebase via Panorama XML API
5. Diff against per-DG baselines, classify changes, alert on violations
6. Update baselines, send email summary

## Project Structure

```
pansyslog/
├── docker-compose.yml
├── Dockerfile
├── config.yaml
├── requirements.txt
├── configs/
│   └── vector-docker.yaml
└── pansyslog/                 # Python package
    ├── __init__.py
    ├── __main__.py            # Entry point
    ├── config.py              # Config loader (YAML + env vars)
    ├── api.py                 # Panorama XML API client
    ├── diff.py                # Rule parsing + baseline diffing
    ├── alerts.py              # Alert classification logic
    ├── email_alert.py         # SMTP alerting
    ├── check.py               # Per-device-group check orchestration
    └── server.py              # Webhook server with debounce
```

## Data Directory

Defaults to `/data` (Docker) or `./data` (local via `DATA_DIR` env var):

```
data/
├── baselines/
│   ├── <DG-name>_pre_baseline.json    # Per-DG pre-rulebase baseline
│   ├── <DG-name>_post_baseline.json   # Per-DG post-rulebase baseline
│   └── remote_access_apps.json        # Cached RA app list (24h TTL)
└── logs/
    ├── alerts.json          # Alert history (JSONL)
    └── all_syslog.log       # Raw syslog from Vector
```
