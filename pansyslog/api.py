"""Panorama XML API client — single auth, per-device-group queries."""

import json
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PanoramaClient:
    """Stateful client for Panorama. Authenticates once, queries per device group."""

    def __init__(self, host, user, password, data_dir="/data"):
        self.host = host
        self.user = user
        self.password = password
        self.data_dir = Path(data_dir)
        self._api_key = None

    @property
    def api_key(self):
        if self._api_key is None:
            self._api_key = self._keygen()
        return self._api_key

    def _keygen(self):
        resp = self._get({"type": "keygen", "user": self.user, "password": self.password})
        root = ET.fromstring(resp.text)
        key = root.find(".//key")
        if key is None:
            raise RuntimeError(f"API keygen failed for {self.host}: {resp.text}")
        return key.text

    def _get(self, params, timeout=15):
        url = f"https://{self.host}/api/"
        resp = requests.get(url, params=params, verify=False, timeout=timeout)
        resp.raise_for_status()
        return resp

    # --- Device group enumeration ---

    def list_device_groups(self):
        """Enumerate all device groups configured in Panorama."""
        resp = self._get({
            "type": "config",
            "action": "get",
            "key": self.api_key,
            "xpath": "/config/devices/entry[@name='localhost.localdomain']"
                     "/device-group",
        })
        root = ET.fromstring(resp.text)
        dgs = []
        for entry in root.findall(".//device-group/entry"):
            name = entry.get("name", "")
            if name:
                dgs.append(name)
        return sorted(dgs)

    def resolve_device_groups(self, configured):
        """Resolve 'all' or a list into actual device group names."""
        if configured == "all":
            dgs = self.list_device_groups()
            print(f"[pansyslog] Enumerated {len(dgs)} device groups from Panorama")
            return dgs
        return list(configured)

    # --- Per-device-group rule queries ---

    def _get_dg_rules(self, device_group, rulebase_type):
        """Pull security rules from a device group's pre or post rulebase.

        rulebase_type: 'pre-rulebase' or 'post-rulebase'
        Returns raw XML text.
        """
        xpath = (
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/device-group/entry[@name='{device_group}']"
            f"/{rulebase_type}/security/rules"
        )
        resp = self._get({
            "type": "config",
            "action": "show",
            "key": self.api_key,
            "xpath": xpath,
        })
        return resp.text

    def get_pre_rules(self, device_group):
        """Pull pre-rulebase security rules for a device group."""
        return self._get_dg_rules(device_group, "pre-rulebase")

    def get_post_rules(self, device_group):
        """Pull post-rulebase security rules for a device group."""
        return self._get_dg_rules(device_group, "post-rulebase")

    # --- Shared resources (Panorama-wide, not per-DG) ---

    def get_service_objects(self, device_group):
        """Fetch custom service objects for a device group."""
        xpath = (
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/device-group/entry[@name='{device_group}']"
            f"/service"
        )
        resp = self._get({
            "type": "config",
            "action": "get",
            "key": self.api_key,
            "xpath": xpath,
        })
        root = ET.fromstring(resp.text)
        services = {}
        for entry in root.findall(".//entry"):
            name = entry.get("name", "")
            ports = set()
            for proto in ("tcp", "udp"):
                port_el = entry.find(f"protocol/{proto}/port")
                if port_el is not None and port_el.text:
                    for p in port_el.text.split(","):
                        p = p.strip()
                        if "-" in p:
                            start, end = p.split("-", 1)
                            for i in range(int(start), int(end) + 1):
                                ports.add(str(i))
                        else:
                            ports.add(p)
            if name and ports:
                services[name] = ports
        return services

    def get_shared_service_objects(self):
        """Fetch shared service objects (Panorama-level, inherited by all DGs)."""
        resp = self._get({
            "type": "config",
            "action": "get",
            "key": self.api_key,
            "xpath": "/config/shared/service",
        })
        root = ET.fromstring(resp.text)
        services = {}
        for entry in root.findall(".//entry"):
            name = entry.get("name", "")
            ports = set()
            for proto in ("tcp", "udp"):
                port_el = entry.find(f"protocol/{proto}/port")
                if port_el is not None and port_el.text:
                    for p in port_el.text.split(","):
                        p = p.strip()
                        if "-" in p:
                            start, end = p.split("-", 1)
                            for i in range(int(start), int(end) + 1):
                                ports.add(str(i))
                        else:
                            ports.add(p)
            if name and ports:
                services[name] = ports
        return services

    def get_remote_access_apps(self):
        """Fetch apps with subcategory 'remote-access'. Cached to disk for 24h."""
        cache = self.data_dir / "baselines" / "remote_access_apps.json"
        if cache.exists():
            age = (datetime.now() - datetime.fromtimestamp(cache.stat().st_mtime)).total_seconds()
            if age < 86400:
                return set(json.load(open(cache)))

        resp = self._get({
            "type": "config",
            "action": "get",
            "key": self.api_key,
            "xpath": "/config/predefined/application/entry[subcategory='remote-access']",
        }, timeout=30)
        root = ET.fromstring(resp.text)
        apps = set()
        for entry in root.findall(".//entry"):
            name = entry.get("name", "")
            if name:
                apps.add(name)

        cache.parent.mkdir(parents=True, exist_ok=True)
        with open(cache, "w") as f:
            json.dump(sorted(apps), f)
        print(f"Cached {len(apps)} remote-access apps")
        return apps

    def get_recent_config_log(self, nlogs=10):
        """Pull recent config audit log entries for commit metadata."""
        resp = self._get({
            "type": "log",
            "log-type": "config",
            "key": self.api_key,
            "nlogs": str(nlogs),
        })
        root = ET.fromstring(resp.text)
        job_id = root.findtext(".//job")
        if not job_id:
            return []

        for _ in range(10):
            time.sleep(1)
            resp = self._get({
                "type": "log",
                "action": "get",
                "job-id": job_id,
                "key": self.api_key,
            })
            root = ET.fromstring(resp.text)
            if root.findtext(".//status") == "FIN":
                break

        entries = []
        for entry in root.findall(".//entry"):
            entries.append({
                "time": entry.findtext("time_generated", ""),
                "admin": entry.findtext("admin", "unknown"),
                "client": entry.findtext("client", "unknown"),
                "source_ip": entry.findtext("host", "unknown"),
                "cmd": entry.findtext("cmd", ""),
                "path": entry.findtext("path", ""),
                "full_path": entry.findtext("full-path", ""),
                "result": entry.findtext("result", ""),
                "device_name": entry.findtext("device_name", ""),
                "serial": entry.findtext("serial", ""),
            })
        return entries
