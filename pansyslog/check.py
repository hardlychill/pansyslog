"""Core check logic — pulls config from Panorama, diffs per device group, logs alerts."""

import json
import sys
from datetime import datetime
from pathlib import Path

from .api import PanoramaClient
from .alerts import (
    get_commit_context,
    should_alert,
    alert_type_for,
    format_modified_diff,
)
from .diff import parse_rules, diff_rules, load_baseline, save_baseline


def log_alert(alert_log, alert_type, rule, details, commit_ctx, device_group):
    """Write a single alert entry to the JSONL alert log."""
    ctx = commit_ctx or {}
    alert = {
        "timestamp": datetime.now().isoformat(),
        "alert_type": alert_type,
        "device_group": device_group,
        "rule_name": rule.get("name", rule.get("new", {}).get("name", "unknown")),
        "details": details,
        "changed_by": ctx.get("changed_by", "unknown"),
        "client": ctx.get("client", "unknown"),
        "source_ip": ctx.get("source_ip", "unknown"),
        "commit_time": ctx.get("commit_time", "unknown"),
        "device_name": ctx.get("device_name", "unknown"),
        "serial": ctx.get("serial", "unknown"),
        "rule": rule,
    }
    print(f"\n{'='*60}")
    print(f"ALERT: {alert_type}")
    print(f"Device Group: {device_group}")
    print(f"Rule: {alert['rule_name']}")
    print(f"Changed by: {alert['changed_by']} via {alert['client']} from {alert['source_ip']}")
    print(f"Device: {alert['device_name']} (S/N: {alert['serial']})")
    print(f"Details: {details}")
    print(f"{'='*60}\n")

    alert_log.parent.mkdir(parents=True, exist_ok=True)
    with open(alert_log, "a") as f:
        f.write(json.dumps(alert) + "\n")


def log_info(msg, rule, device_group):
    """Log non-alerting changes for visibility."""
    print(f"[INFO] [{device_group}] {msg} - Rule: {rule.get('name', 'unknown')} "
          f"(from={rule.get('from')}, to={rule.get('to')}) - no alert")


def _check_rule_list(rules, action_label, cfg, ra_apps, service_objects,
                     commit_ctx, device_group, alert_log):
    """Check a list of added or removed rules. Returns alert count."""
    alerts = 0
    for rule in rules:
        triggered, reason = should_alert(rule, cfg, ra_apps, service_objects)
        if triggered:
            log_alert(alert_log, alert_type_for(reason, action_label), rule,
                      f"Rule '{rule['name']}' {action_label.lower()}: "
                      f"{rule['from']} -> {rule['to']}, "
                      f"app={rule['application']}, service={rule.get('service', ['?'])}, "
                      f"action={rule['action']}. Trigger: {reason}",
                      commit_ctx, device_group)
            alerts += 1
        else:
            log_info(f"Rule {action_label.lower()}", rule, device_group)
    return alerts


def _check_dg_rulebase(rulebase_label, rules_xml, baseline_file, cfg,
                       ra_apps, service_objects, commit_ctx, device_group, alert_log):
    """Diff one rulebase (pre or post) for a device group. Returns alert count."""
    current_rules = parse_rules(rules_xml)
    baseline_rules = load_baseline(baseline_file)
    alerts = 0

    if baseline_rules is not None:
        added, removed, modified = diff_rules(baseline_rules, current_rules)

        if not added and not removed and not modified:
            pass  # no changes
        else:
            print(f"  [{device_group}/{rulebase_label}] "
                  f"+{len(added)} added, -{len(removed)} removed, ~{len(modified)} modified")

            alerts += _check_rule_list(added, "ADDED", cfg, ra_apps,
                                       service_objects, commit_ctx, device_group, alert_log)
            alerts += _check_rule_list(removed, "REMOVED", cfg, ra_apps,
                                       service_objects, commit_ctx, device_group, alert_log)

            for change in modified:
                new_rule = change["new"]
                old_rule = change["old"]
                new_triggered, new_reason = should_alert(new_rule, cfg, ra_apps, service_objects)
                old_triggered, old_reason = should_alert(old_rule, cfg, ra_apps, service_objects)
                if new_triggered or old_triggered:
                    reason = new_reason or old_reason
                    diff_str = format_modified_diff(old_rule, new_rule)
                    log_alert(alert_log, alert_type_for(reason, "MODIFIED"), change,
                              f"Rule '{new_rule['name']}' modified: {diff_str}. "
                              f"Now: {new_rule['from']} -> {new_rule['to']}, "
                              f"app={new_rule['application']}, service={new_rule.get('service', ['?'])}, "
                              f"action={new_rule['action']}. Trigger: {reason}",
                              commit_ctx, device_group)
                    alerts += 1
                else:
                    log_info("Rule modified", new_rule, device_group)
    else:
        print(f"  [{device_group}/{rulebase_label}] No baseline — saving {len(current_rules)} rules")

    save_baseline(baseline_file, current_rules)
    return alerts


def run_check(cfg, client=None):
    """Run a full check cycle across all device groups. Returns total new alerts."""
    pan_cfg = cfg["panorama"]
    data_dir = Path(cfg["data_dir"])
    alert_log = data_dir / "logs" / "alerts.json"

    print(f"\n[{datetime.now().isoformat()}] Checking Panorama ({pan_cfg['host']})...")

    if client is None:
        client = PanoramaClient(
            pan_cfg["host"], pan_cfg["user"], pan_cfg["password"],
            data_dir=cfg["data_dir"],
        )

    # Resolve device groups
    try:
        device_groups = client.resolve_device_groups(pan_cfg["device_groups"])
    except Exception as e:
        print(f"ERROR: Failed to enumerate device groups: {e}", file=sys.stderr)
        return 0

    # Fetch shared resources once (Panorama-wide)
    try:
        ra_apps = client.get_remote_access_apps()
        print(f"Loaded {len(ra_apps)} remote-access apps")
    except Exception as e:
        print(f"WARNING: Could not fetch remote-access apps: {e}")
        ra_apps = set()

    try:
        shared_services = client.get_shared_service_objects()
        if shared_services:
            print(f"Loaded {len(shared_services)} shared service objects")
    except Exception as e:
        print(f"WARNING: Could not fetch shared service objects: {e}")
        shared_services = {}

    try:
        config_log = client.get_recent_config_log()
        commit_ctx = get_commit_context(config_log)
        print(f"Last commit by: {commit_ctx['changed_by']} via {commit_ctx['client']} "
              f"from {commit_ctx['source_ip']}")
    except Exception as e:
        print(f"WARNING: Could not fetch config log: {e}")
        commit_ctx = {}

    total_alerts = 0

    for dg in device_groups:
        print(f"\n  Checking device group: {dg}")

        # Merge shared + DG-specific service objects
        try:
            dg_services = client.get_service_objects(dg)
        except Exception as e:
            print(f"  WARNING: Could not fetch service objects for {dg}: {e}")
            dg_services = {}
        service_objects = {**shared_services, **dg_services}

        # Check pre-rulebase
        try:
            pre_xml = client.get_pre_rules(dg)
            pre_baseline = data_dir / "baselines" / f"{dg}_pre_baseline.json"
            total_alerts += _check_dg_rulebase(
                "pre", pre_xml, pre_baseline, cfg,
                ra_apps, service_objects, commit_ctx, dg, alert_log,
            )
        except Exception as e:
            print(f"  WARNING: Could not check pre-rulebase for {dg}: {e}")

        # Check post-rulebase
        try:
            post_xml = client.get_post_rules(dg)
            post_baseline = data_dir / "baselines" / f"{dg}_post_baseline.json"
            total_alerts += _check_dg_rulebase(
                "post", post_xml, post_baseline, cfg,
                ra_apps, service_objects, commit_ctx, dg, alert_log,
            )
        except Exception as e:
            print(f"  WARNING: Could not check post-rulebase for {dg}: {e}")

    print(f"\nCheck complete: {len(device_groups)} device groups, {total_alerts} new alerts")
    return total_alerts
