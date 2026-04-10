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
    """Stateful client for Panorama. Authenticates once, re-auths on expiry."""

    def __init__(self, host, user, password, data_dir="/data"):
        self.host = host
        self.user = user
        self.password = password
        self.data_dir = Path(data_dir)
        self._api_key = None
        self._key_time = None

    @property
    def api_key(self):
        if self._api_key is None:
            self._refresh_key()
        return self._api_key

    def _refresh_key(self):
        """Generate a new API key."""
        url = f"https://{self.host}/api/"
        resp = requests.get(url, params={
            "type": "keygen", "user": self.user, "password": self.password,
        }, verify=False, timeout=15)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError:
            raise RuntimeError(
                f"API keygen failed for {self.host} "
                f"(HTTP {resp.status_code} — check user/password and XML API permissions)"
            )
        root = ET.fromstring(resp.text)
        key = root.find(".//key")
        if key is None:
            raise RuntimeError(f"API keygen failed for {self.host}: no key in response")
        self._api_key = key.text
        self._key_time = datetime.now()
        print(f"[pansyslog] API key obtained for {self.host}")

    def _get(self, params, timeout=15, _retried=False):
        """Make an API GET request. Auto-retries once with a fresh key on 403."""
        url = f"https://{self.host}/api/"
        resp = requests.get(url, params=params, verify=False, timeout=timeout)

        if resp.status_code == 403 and not _retried and params.get("type") != "keygen":
            print(f"[pansyslog] API key expired or invalid, re-authenticating...")
            self._refresh_key()
            # Swap the old key for the new one in params
            if "key" in params:
                params["key"] = self._api_key
            return self._get(params, timeout=timeout, _retried=True)

        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError:
            msg = f"{resp.status_code} API error from {self.host}"
            if resp.status_code == 403:
                msg += " (authentication failed — check user/password and XML API permissions)"
            raise RuntimeError(msg)
        return resp

    # --- Device group enumeration ---

    def _list_template_names(self):
        """Fetch all template and template-stack names to exclude from DG list."""
        names = set()
        for xpath in (
            "/config/devices/entry[@name='localhost.localdomain']/template",
            "/config/devices/entry[@name='localhost.localdomain']/template-stack",
        ):
            try:
                resp = self._get({
                    "type": "config",
                    "action": "get",
                    "key": self.api_key,
                    "xpath": xpath,
                })
                root = ET.fromstring(resp.text)
                for entry in root.findall(".//entry"):
                    name = entry.get("name", "")
                    if name:
                        names.add(name)
            except Exception:
                pass
        return names

    def list_device_groups(self):
        """Enumerate all device groups configured in Panorama.
        Excludes templates and template-stacks by cross-referencing."""
        template_names = self._list_template_names()
        if template_names:
            print(f"[pansyslog] Found {len(template_names)} templates/stacks to exclude")

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
            if not name:
                continue
            if name in template_names:
                continue
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
        """Pull security rules from a device group's pre or post rulebase."""
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
        return self._parse_service_objects(resp.text)

    def get_shared_service_objects(self):
        """Fetch shared service objects (Panorama-level, inherited by all DGs)."""
        resp = self._get({
            "type": "config",
            "action": "get",
            "key": self.api_key,
            "xpath": "/config/shared/service",
        })
        return self._parse_service_objects(resp.text)

    @staticmethod
    def _parse_service_objects(xml_text):
        """Parse service object XML into {name: set(ports)} dict."""
        root = ET.fromstring(xml_text)
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

    def _get_apps_by_subcategory(self, subcategory):
        """Fetch app names by PAN-OS subcategory. Cached to disk for 24h."""
        cache = self.data_dir / "baselines" / f"{subcategory}_apps.json"
        if cache.exists():
            age = (datetime.now() - datetime.fromtimestamp(cache.stat().st_mtime)).total_seconds()
            if age < 86400:
                return set(json.load(open(cache)))

        resp = self._get({
            "type": "config",
            "action": "get",
            "key": self.api_key,
            "xpath": f"/config/predefined/application/entry[subcategory='{subcategory}']",
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
        print(f"Cached {len(apps)} {subcategory} apps")
        return apps

    def get_remote_access_apps(self):
        """Fetch apps with subcategory 'remote-access'. Cached to disk for 24h."""
        return self._get_apps_by_subcategory("remote-access")

    def get_file_sharing_apps(self):
        """Fetch apps with subcategory 'file-sharing'. Cached to disk for 24h."""
        return self._get_apps_by_subcategory("file-sharing")

    def get_recent_config_log(self, nlogs=50):
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
