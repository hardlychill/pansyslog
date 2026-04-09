"""Entry point: python -m pansyslog"""

from .config import load_config
from .server import WebhookServer


def main():
    cfg = load_config()
    pan = cfg.get("panorama", {})
    if not pan.get("host"):
        print("[pansyslog] ERROR: No Panorama host configured.")
        print("  Set PAN_HOST env var, or add panorama.host to config.yaml")
        raise SystemExit(1)
    server = WebhookServer(cfg)
    server.serve()


if __name__ == "__main__":
    main()
