"""Alert classification — decides which rule changes are dangerous."""


def get_commit_context(config_log):
    """Extract recent commit metadata from config log.

    Returns all unique committers since we can't reliably map individual
    rule changes to specific commits. The alert will list all admins who
    committed recently so the recipient can investigate.
    """
    commits = []
    seen = set()
    for entry in config_log:
        if entry["cmd"] == "commit" and entry["admin"] not in seen:
            seen.add(entry["admin"])
            commits.append({
                "changed_by": entry["admin"],
                "client": entry["client"],
                "source_ip": entry["source_ip"],
                "commit_time": entry["time"],
                "device_name": entry["device_name"],
                "serial": entry["serial"],
            })

    if not commits and config_log:
        e = config_log[0]
        commits.append({
            "changed_by": e["admin"],
            "client": e["client"],
            "source_ip": e["source_ip"],
            "commit_time": e["time"],
            "device_name": e["device_name"],
            "serial": e["serial"],
        })

    if not commits:
        commits.append({
            "changed_by": "unknown",
            "client": "unknown",
            "source_ip": "unknown",
            "commit_time": "unknown",
            "device_name": "unknown",
            "serial": "unknown",
        })

    # Build a merged context — primary is most recent, but list all committers
    ctx = dict(commits[0])
    if len(commits) > 1:
        all_admins = [c["changed_by"] for c in commits]
        ctx["changed_by"] = ", ".join(all_admins)
        ctx["recent_commits"] = commits
    return ctx


def _zones_match_prefix(zones, prefix):
    """Check if any zone in the set starts with the given prefix."""
    return any(z.startswith(prefix) for z in zones)


def rule_involves_alert_zones(rule, alert_zone_prefixes):
    """Check if a rule allows traffic between alert zone prefix pairs.

    alert_zone_prefixes is a list of (prefix_a, prefix_b) tuples.
    Alerts if any from-zone matches one prefix and any to-zone matches the other
    (in either direction). Zone 'any' matches all prefixes.
    """
    from_zones = set(rule["from"])
    to_zones = set(rule["to"])
    has_any_from = "any" in from_zones
    has_any_to = "any" in to_zones

    for prefix_a, prefix_b in alert_zone_prefixes:
        a_in_from = has_any_from or _zones_match_prefix(from_zones, prefix_a)
        b_in_to = has_any_to or _zones_match_prefix(to_zones, prefix_b)
        b_in_from = has_any_from or _zones_match_prefix(from_zones, prefix_b)
        a_in_to = has_any_to or _zones_match_prefix(to_zones, prefix_a)

        # Either direction: A->B or B->A
        if (a_in_from and b_in_to) or (b_in_from and a_in_to):
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

    if rule_involves_alert_zones(rule, cfg["alert_zone_prefixes"]):
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
