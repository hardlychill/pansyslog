# Panorama Syslog Configuration for pansyslog

This guide walks through configuring Panorama to send the syslog events that pansyslog needs to detect rule changes.

pansyslog only needs **config logs** from Panorama itself — not traffic logs from managed firewalls. This keeps syslog volume low.

## What pansyslog listens for

Vector filters syslog for messages containing: `config`, `commit`, `rule`, `security`, `policy`. These appear in PAN-OS config audit logs when admins create, modify, delete, or commit security rules.

## Prerequisites

- Panorama management IP can reach the pansyslog host on **UDP 5514**
- Network/firewall rules allow this traffic
- You know the IP address of the server running pansyslog

## Step 1: Create a Syslog Server Profile

1. Log in to **Panorama** web UI
2. Go to **Panorama > Server Profiles > Syslog**
3. Click **Add** and name it `pansyslog-server`
4. Under **Servers**, click **Add**:
   - **Name:** `pansyslog`
   - **Syslog Server:** `<pansyslog-host-ip>` (the IP where Docker/Vector is running)
   - **Transport:** `UDP`
   - **Port:** `5514`
   - **Format:** `BSD`
   - **Facility:** `LOG_USER`
5. Click **OK** to save the server profile

## Step 2: Create a Log Forwarding Profile

1. Go to **Panorama > Log Settings**
2. Under **Config Log**, click the **edit (gear) icon**
3. Click **Add** to add a match list entry:
   - **Name:** `pansyslog-config`
   - **Filter:** `All Logs` (or leave default to capture all config events)
   - **Syslog:** Select `pansyslog-server`
4. Click **OK**

This sends all configuration audit log entries (rule edits, commits, admin actions) to pansyslog.

## Step 3: (Optional) Also forward System Logs

System logs can provide additional context (admin logins, commit success/failure).

1. Under **Panorama > Log Settings > System Log**
2. Click **Add**:
   - **Name:** `pansyslog-system`
   - **Filter:** `All Logs` (or filter to severity `informational` and above)
   - **Syslog:** Select `pansyslog-server`
3. Click **OK**

## Step 4: Commit

1. Click **Commit** > **Commit to Panorama**
2. This only needs to be committed on Panorama itself — no push to managed firewalls required

## Verification

After committing, trigger a test by making a minor rule change in any device group and committing it. Then check:

```bash
# If running Docker:
docker logs pansyslog-vector 2>&1 | tail -20

# Check if syslog is arriving:
docker exec pansyslog-vector cat /data/logs/all_syslog.log | tail -5

# Check if webhook fired:
docker logs pansyslog 2>&1 | tail -20
```

You should see syslog entries from Panorama and webhook check output from pansyslog.

## Firewall requirements

pansyslog also needs **XML API access** to Panorama to pull rule configurations:

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| pansyslog host | Panorama mgmt IP | 443 | TCP/HTTPS | XML API queries |
| Panorama mgmt IP | pansyslog host | 5514 | UDP | Syslog delivery |

## API user (recommended)

Instead of using an admin account, create a dedicated API-only user:

1. Go to **Panorama > Administrators**
2. Click **Add**:
   - **Name:** `pansyslog-api`
   - **Authentication Profile:** (your auth profile or local)
   - **Administrator Type:** Custom Panorama Admin
3. Create an **Admin Role** with minimum permissions:
   - **XML API:** Configuration (read-only), Log (read-only)
   - **Web UI:** No access needed
4. Assign the role to the `pansyslog-api` user
5. Commit to Panorama

Use these credentials in `config.yaml` or `PAN_USER` / `PAN_PASS` env vars.

## Troubleshooting

**No syslog arriving:**
- Verify Panorama can reach pansyslog host: `ping <pansyslog-ip>` from Panorama CLI
- Check that UDP 5514 is open (no firewall blocking between Panorama and pansyslog host)
- Verify the syslog server profile is committed (not just saved)
- Check Vector is listening: `docker logs pansyslog-vector` should show startup message

**Syslog arrives but no alerts:**
- pansyslog only alerts after a **commit** (not on candidate config changes)
- First run creates a baseline — alerts start on the second commit with changes
- Check `docker logs pansyslog` for check output

**API errors:**
- Verify Panorama IP and credentials in `config.yaml`
- Ensure the API user has read access to config and logs
- Test API manually: `curl -k "https://<panorama>/api/?type=keygen&user=<user>&password=<pass>"`
