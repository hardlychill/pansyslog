"""Alert classification — decides which rule changes are dangerous."""


def get_commit_context(config_log):
    """Extract the most recent commit's admin/client/ip from config log."""
    for entry in config_log:
        if entry["cmd"] == "commit":
            return {
                "changed_by": entry["admin"],
                "client": entry["client"],
                "source_ip": entry["source_ip"],
                "commit_time": entry["time"],
                "device_name": entry["device_name"],
                "serial": entry["serial"],
            }
    if config_log:
        e = config_log[0]
        return {
            "changed_by": e["admin"],
            "client": e["client"],
            "source_ip": e["source_ip"],
            "commit_time": e["time"],
            "device_name": e["device_name"],
            "serial": e["serial"],
        }
    return {
        "changed_by": "unknown",
        "client": "unknown",
        "source_ip": "unknown",
        "commit_time": "unknown",
        "device_name": "unknown",
        "serial": "unknown",
    }


def rule_involves_alert_zones(rule, alert_zone_pairs):
    """Check if a rule involves an alertable zone pair."""
    from_zones = set(rule["from"])
    to_zones = set(rule["to"])

    if "any" in from_zones or "any" in to_zones:
        return True

    for pair in alert_zone_pairs:
        if (from_zones & pair) and (to_zones & pair):
            return True

    return False


def rule_has_remote_access(rule, ra_apps, service_objects, ra_ports):
    """Check if a rule allows remote-access apps or ports.
    Returns (True, reason) or (False, None)."""
    apps = set(rule.get("application", []))
    services = set(rule.get("service", []))

    if "any" in apps and "any" in services:
        return True, "application=any + service=any (allows all remote access)"

    ra_match = apps & ra_apps
    if ra_match:
        return True, f"remote-access app(s): {sorted(ra_match)}"

    if "any" in apps or not apps:
        for svc in services:
            if svc == "any":
                return True, "service=any (allows all ports including remote-access)"
            if svc in service_objects:
                matched_ports = service_objects[svc] & ra_ports
                if matched_ports:
                    return True, f"service '{svc}' uses remote-access port(s): {sorted(matched_ports)}"

    return False, None


def should_alert(rule, cfg, ra_apps=None, service_objects=None):
    """Determine if a rule change should trigger an alert.
    Returns (should_alert: bool, reason: str|None)."""
    if rule.get("action") in ("deny", "drop", "reset-client", "reset-server", "reset-both"):
        return False, None

    if rule_involves_alert_zones(rule, cfg["alert_zone_pairs"]):
        return True, "insecure-zone"

    if ra_apps is not None and service_objects is not None:
        is_ra, ra_reason = rule_has_remote_access(
            rule, ra_apps, service_objects, cfg["remote_access_port_set"]
        )
        if is_ra:
            return True, f"remote-access: {ra_reason}"

    return False, None


def alert_type_for(reason, action):
    """Map trigger reason + action (added/removed/modified) to alert type string."""
    action = action.upper()
    if reason and reason.startswith("remote-access"):
        return f"REMOTE_ACCESS_RULE_{action}"
    return f"BREAK_OF_SEGMENTATION_{action}"


def format_modified_diff(old_rule, new_rule):
    """Build a human-readable field-by-field diff string for a modified rule."""
    diffs = []
    for field in ("from", "to", "source", "destination", "application",
                  "service", "action", "disabled", "has_security_profile"):
        old_val = old_rule.get(field)
        new_val = new_rule.get(field)
        if old_val != new_val:
            diffs.append(f"{field}: {old_val} -> {new_val}")
    return "; ".join(diffs) if diffs else "unknown change"
