"""Configuration loader — reads config.yaml and merges with env var overrides."""

import os
from pathlib import Path

import yaml


DEFAULT_CONFIG = {
    "panorama": {
        "host": "",
        "user": "admin",
        "password": "",
        "device_groups": "all",
    },
    "alert_zones": [["untrust-WAN", "trust-GOOD"]],
    "remote_access_ports": [
        "22", "23", "3389", "5900", "5901", "5902", "5800",
        "4899", "5938", "3283", "5631", "5632", "1494", "2598",
        "8200", "6568", "4172",
    ],
    "debounce_seconds": 30,
    "webhook_port": 8787,
    "email": {
        "enabled": False,
        "to": "",
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_pass": "",
    },
    "data_dir": "/data",
}


def load_config(path=None):
    """Load config from YAML file, with env var overrides.

    Env overrides:
        PAN_HOST, PAN_USER, PAN_PASS  — Panorama connection
        SMTP_USER, SMTP_PASS          — email credentials
        SMTP_HOST, SMTP_PORT          — email server
        EMAIL_TO                      — alert recipient
        WEBHOOK_PORT                  — webhook listen port
        DEBOUNCE_SECONDS              — debounce window
        DATA_DIR                      — baselines/logs directory
    """
    cfg = {
        **DEFAULT_CONFIG,
        "panorama": dict(DEFAULT_CONFIG["panorama"]),
        "email": dict(DEFAULT_CONFIG["email"]),
    }

    # Load YAML if it exists
    if path is None:
        path = os.environ.get("PANSYSLOG_CONFIG", "/etc/pansyslog/config.yaml")
    path = Path(path)
    if path.exists():
        with open(path) as f:
            file_cfg = yaml.safe_load(f) or {}
        for k, v in file_cfg.items():
            if k in ("panorama", "email") and isinstance(v, dict):
                cfg[k].update(v)
            else:
                cfg[k] = v

    # Env var overrides — Panorama
    if os.environ.get("PAN_HOST"):
        cfg["panorama"]["host"] = os.environ["PAN_HOST"]
    if os.environ.get("PAN_USER"):
        cfg["panorama"]["user"] = os.environ["PAN_USER"]
    if os.environ.get("PAN_PASS"):
        cfg["panorama"]["password"] = os.environ["PAN_PASS"]

    # Env var overrides — email
    if os.environ.get("SMTP_USER"):
        cfg["email"]["smtp_user"] = os.environ["SMTP_USER"]
    if os.environ.get("SMTP_PASS"):
        cfg["email"]["smtp_pass"] = os.environ["SMTP_PASS"]
    if os.environ.get("SMTP_HOST"):
        cfg["email"]["smtp_host"] = os.environ["SMTP_HOST"]
    if os.environ.get("SMTP_PORT"):
        cfg["email"]["smtp_port"] = int(os.environ["SMTP_PORT"])
    if os.environ.get("EMAIL_TO"):
        cfg["email"]["to"] = os.environ["EMAIL_TO"]
        cfg["email"]["enabled"] = True

    # Env var overrides — general
    if os.environ.get("WEBHOOK_PORT"):
        cfg["webhook_port"] = int(os.environ["WEBHOOK_PORT"])
    if os.environ.get("DEBOUNCE_SECONDS"):
        cfg["debounce_seconds"] = int(os.environ["DEBOUNCE_SECONDS"])
    if os.environ.get("DATA_DIR"):
        cfg["data_dir"] = os.environ["DATA_DIR"]

    # Auto-enable email if credentials are present
    if cfg["email"]["smtp_user"] and cfg["email"]["smtp_pass"] and cfg["email"]["to"]:
        cfg["email"]["enabled"] = True

    # Normalize alert_zones to frozensets
    cfg["alert_zone_pairs"] = {frozenset(pair) for pair in cfg["alert_zones"]}
    cfg["remote_access_port_set"] = set(cfg["remote_access_ports"])

    # Ensure data_dir exists
    data = Path(cfg["data_dir"])
    (data / "baselines").mkdir(parents=True, exist_ok=True)
    (data / "logs").mkdir(parents=True, exist_ok=True)

    return cfg
