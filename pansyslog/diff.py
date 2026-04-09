"""Rule parsing, baseline management, and diffing."""

import json
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_rules(xml_text):
    """Parse security rules XML into a list of dicts."""
    root = ET.fromstring(xml_text)
    rules_el = root.find(".//rules")
    if rules_el is None:
        return []

    rules = []
    for entry in rules_el.findall("entry"):
        name = entry.get("name", "unnamed")
        from_zones = [m.text for m in entry.findall("from/member")] if entry.find("from") is not None else ["any"]
        to_zones = [m.text for m in entry.findall("to/member")] if entry.find("to") is not None else ["any"]
        source = [m.text for m in entry.findall("source/member")] if entry.find("source") is not None else ["any"]
        destination = [m.text for m in entry.findall("destination/member")] if entry.find("destination") is not None else ["any"]
        application = [m.text for m in entry.findall("application/member")] if entry.find("application") is not None else ["any"]
        service = [m.text for m in entry.findall("service/member")] if entry.find("service") is not None else ["application-default"]
        action_el = entry.find("action")
        action = action_el.text if action_el is not None else "unknown"
        disabled = entry.find("disabled")
        is_disabled = disabled is not None and disabled.text == "yes"
        profile_group = entry.find("profile-setting/group/member")
        has_profile = profile_group is not None

        rules.append({
            "name": name,
            "from": from_zones,
            "to": to_zones,
            "source": source,
            "destination": destination,
            "application": application,
            "service": service,
            "action": action,
            "disabled": is_disabled,
            "has_security_profile": has_profile,
        })
    return rules


def diff_rules(baseline, current):
    """Compare baseline and current rules, return (added, removed, modified)."""
    baseline_map = {r["name"]: r for r in baseline}
    current_map = {r["name"]: r for r in current}

    added = [current_map[n] for n in current_map if n not in baseline_map]
    removed = [baseline_map[n] for n in baseline_map if n not in current_map]
    modified = []
    for name in baseline_map:
        if name in current_map and baseline_map[name] != current_map[name]:
            modified.append({"old": baseline_map[name], "new": current_map[name]})

    return added, removed, modified


def load_baseline(path):
    """Load baseline rules from JSON file."""
    path = Path(path)
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None


def save_baseline(path, rules):
    """Save current rules as new baseline."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(rules, f, indent=2)
