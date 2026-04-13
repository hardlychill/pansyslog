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
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# --- Proxy helpers ---

async def api_get(path):
    """GET from pansyslog API."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{PANSYSLOG_API}{path}")
        return resp.json()


async def api_post(path, data=None):
    """POST to pansyslog API."""
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(f"{PANSYSLOG_API}{path}", json=data or {})
        return resp.json()


# --- Pages ---

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    health = await api_get("/health")
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "health": health, "page": "dashboard",
    })


@app.get("/active-alerts", response_class=HTMLResponse)
async def active_alerts_page(request: Request):
    alerts = await api_get("/active-alerts")
    return templates.TemplateResponse("active_alerts.html", {
        "request": request, "alerts": alerts, "page": "active_alerts",
    })


@app.get("/alert-history", response_class=HTMLResponse)
async def alert_history_page(request: Request):
    alerts = await api_get("/alerts")
    return templates.TemplateResponse("alert_history.html", {
        "request": request, "alerts": alerts, "page": "alert_history",
    })


@app.get("/device-groups", response_class=HTMLResponse)
async def device_groups_page(request: Request):
    baselines = await api_get("/baselines")
    check_history = await api_get("/check-history")
    latest = check_history[-1] if check_history else None
    return templates.TemplateResponse("device_groups.html", {
        "request": request, "baselines": baselines, "latest_check": latest,
        "page": "device_groups",
    })


@app.get("/baselines", response_class=HTMLResponse)
async def baselines_page(request: Request):
    baselines = await api_get("/baselines")
    return templates.TemplateResponse("baselines.html", {
        "request": request, "baselines": baselines, "page": "baselines",
    })


@app.get("/baselines/{name}", response_class=HTMLResponse)
async def baseline_detail(request: Request, name: str):
    baseline_file = DATA_DIR / "baselines" / f"{name}.json"
    rules = []
    if baseline_file.exists():
        with open(baseline_file) as f:
            rules = json.load(f)
    return templates.TemplateResponse("baseline_detail.html", {
        "request": request, "name": name, "rules": rules, "page": "baselines",
    })


@app.get("/check-history", response_class=HTMLResponse)
async def check_history_page(request: Request):
    history = await api_get("/check-history")
    history.reverse()  # newest first
    return templates.TemplateResponse("check_history.html", {
        "request": request, "history": history, "page": "check_history",
    })


@app.get("/troubleshooting", response_class=HTMLResponse)
async def troubleshooting_page(request: Request):
    health = await api_get("/health")
    return templates.TemplateResponse("troubleshooting.html", {
        "request": request, "health": health, "page": "troubleshooting",
    })


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
