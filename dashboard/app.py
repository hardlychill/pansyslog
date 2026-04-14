"""pansyslog dashboard — web UI for alert management and monitoring."""

import json
import os
from datetime import datetime
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

PANSYSLOG_API = os.environ.get("PANSYSLOG_API", "http://pansyslog:8787")
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))

app = FastAPI(title="pansyslog dashboard")
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_dir))
# Disable Jinja2 cache to avoid Python 3.14 compatibility issues
templates.env.auto_reload = True
templates.env.cache = None


# --- Proxy helpers ---

async def api_get(path):
    """GET from pansyslog API. Returns empty dict/list on failure."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{PANSYSLOG_API}{path}")
            return resp.json()
    except Exception:
        return {}


async def api_post(path, data=None):
    """POST to pansyslog API. Returns error dict on failure."""
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(f"{PANSYSLOG_API}{path}", json=data or {})
            return resp.json()
    except Exception as e:
        return {"error": str(e)}


# --- Pages ---

def _render(request, name, ctx):
    """Render template — compatible with both old and new Starlette API."""
    return templates.TemplateResponse(request, name, ctx)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    health = await api_get("/health")
    return _render(request, "dashboard.html", {"health": health, "page": "dashboard"})


@app.get("/active-alerts", response_class=HTMLResponse)
async def active_alerts_page(request: Request):
    alerts = await api_get("/active-alerts")
    return _render(request, "active_alerts.html", {"alerts": alerts, "page": "active_alerts"})


@app.get("/alert-history", response_class=HTMLResponse)
async def alert_history_page(request: Request):
    alerts = await api_get("/alerts")
    if not isinstance(alerts, list):
        alerts = []
    return _render(request, "alert_history.html", {"alerts": alerts, "page": "alert_history"})


@app.get("/device-groups", response_class=HTMLResponse)
async def device_groups_page(request: Request):
    baselines = await api_get("/baselines")
    check_history = await api_get("/check-history")
    if not isinstance(check_history, list):
        check_history = []
    latest = check_history[-1] if check_history else None
    return _render(request, "device_groups.html", {
        "baselines": baselines, "latest_check": latest, "page": "device_groups",
    })


@app.get("/baselines", response_class=HTMLResponse)
async def baselines_page(request: Request):
    baselines = await api_get("/baselines")
    return _render(request, "baselines.html", {"baselines": baselines, "page": "baselines"})


@app.get("/baselines/{name}", response_class=HTMLResponse)
async def baseline_detail(request: Request, name: str):
    baseline_file = DATA_DIR / "baselines" / f"{name}.json"
    rules = []
    if baseline_file.exists():
        with open(baseline_file) as f:
            rules = json.load(f)
    return _render(request, "baseline_detail.html", {
        "name": name, "rules": rules, "page": "baselines",
    })


@app.get("/check-history", response_class=HTMLResponse)
async def check_history_page(request: Request):
    history = await api_get("/check-history")
    if not isinstance(history, list):
        history = []
    history.reverse()
    return _render(request, "check_history.html", {"history": history, "page": "check_history"})


@app.get("/troubleshooting", response_class=HTMLResponse)
async def troubleshooting_page(request: Request):
    health = await api_get("/health")
    return _render(request, "troubleshooting.html", {"health": health, "page": "troubleshooting"})


# --- API actions (proxied to pansyslog) ---

@app.post("/api/check")
async def trigger_check():
    return await api_post("/check")


@app.post("/api/acknowledge")
async def acknowledge(request: Request):
    body = await request.json()
    return await api_post("/acknowledge", body)


@app.post("/api/baseline/reset")
async def reset_baseline(request: Request):
    body = await request.json()
    return await api_post("/baseline/reset", body)


@app.post("/api/reauth")
async def reauth():
    return await api_post("/reauth")


# --- Data API (direct read for CSV export) ---

@app.get("/api/alerts/export")
async def export_alerts():
    alert_log = DATA_DIR / "logs" / "alerts.json"
    if not alert_log.exists():
        return JSONResponse({"error": "no alerts"}, status_code=404)

    import csv
    import io

    alerts = []
    with open(alert_log) as f:
        for line in f:
            line = line.strip()
            if line:
                alerts.append(json.loads(line))

    if not alerts:
        return JSONResponse({"error": "no alerts"}, status_code=404)

    output = io.StringIO()
    fields = ["timestamp", "alert_type", "device_group", "rule_name",
              "changed_by", "client", "source_ip", "commit_time", "details"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for alert in alerts:
        writer.writerow(alert)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=pansyslog_alerts_{datetime.now():%Y%m%d}.csv"},
    )
