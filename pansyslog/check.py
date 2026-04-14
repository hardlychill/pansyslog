"""Core check logic — pulls config from Panorama, diffs per device group, logs alerts."""

import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
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

# Track DGs that consistently fail so we don't spam logs
_dg_failures = {}  # {dg_name: consecutive_failure_count}
_SUPPRESS_AFTER = 3  # suppress warnings after this many consecutive failures
_alert_log_lock = threading.Lock()


SYSTEM_ALERT_TYPES = {"BASELINE_ANOMALY_PRE", "BASELINE_ANOMALY_POST"}


def log_alert(alert_log, alert_type, rule, details, commit_ctx, device_group,
              tracker=None):
    """Write a single alert entry to the JSONL alert log."""
    ctx = commit_ctx or {}
    category = "system" if alert_type in SYSTEM_ALERT_TYPES else "firewall"
    alert = {
        "timestamp": datetime.now().isoformat(),
        "alert_type": alert_type,
        "category": category,
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

    with _alert_log_lock:
        alert_log.parent.mkdir(parents=True, exist_ok=True)
        with open(alert_log, "a") as f:
            f.write(json.dumps(alert) + "\n")

    # Track as unacknowledged
    if tracker is not None:
        tracker.record(device_group, alert["rule_name"], alert_type, details)


def log_info(msg, rule, device_group):
    """Log non-alerting changes for visibility."""
    print(f"[INFO] [{device_group}] {msg} - Rule: {rule.get('name', 'unknown')} "
          f"(from={rule.get('from')}, to={rule.get('to')}) - no alert")


def _dg_warn(dg, rulebase, error):
    """Log a DG failure, suppressing after repeated consecutive failures."""
    key = f"{dg}/{rulebase}"
    count = _dg_failures.get(key, 0) + 1
    _dg_failures[key] = count

    if count == _SUPPRESS_AFTER:
        print(f"  WARNING: {key} has failed {count} times consecutively, suppressing further warnings")
    elif count < _SUPPRESS_AFTER:
        print(f"  WARNING: Could not check {key}: {error}")
    # else: suppressed


def _dg_ok(dg, rulebase):
    """Clear failure tracking for a DG that succeeded. Log recovery if it was failing."""
    key = f"{dg}/{rulebase}"
    if key in _dg_failures:
        if _dg_failures[key] >= _SUPPRESS_AFTER:
            print(f"  [RECOVERED] {key} is responding again")
        del _dg_failures[key]


def _check_rule_list(rules, action_label, cfg, ra_apps, service_objects,
                     commit_ctx, device_group, alert_log, tracker=None, fs_apps=None):
    """Check a list of added or removed rules. Returns alert count."""
    alerts = 0
    for rule in rules:
        triggered, reason = should_alert(rule, cfg, ra_apps, service_objects, fs_apps=fs_apps)
        if triggered:
            log_alert(alert_log, alert_type_for(reason, action_label), rule,
                      f"Rule '{rule['name']}' {action_label.lower()}: "
                      f"{rule['from']} -> {rule['to']}, "
                      f"app={rule['application']}, service={rule.get('service', ['?'])}, "
                      f"action={rule['action']}. Trigger: {reason}",
                      commit_ctx, device_group, tracker=tracker)
            alerts += 1
        else:
            log_info(f"Rule {action_label.lower()}", rule, device_group)
    return alerts


def _check_dg_rulebase(rulebase_label, rules_xml, baseline_file, cfg,
                       ra_apps, service_objects, commit_ctx, device_group, alert_log,
                       tracker=None, fs_apps=None):
    """Diff one rulebase (pre or post) for a device group. Returns (alert_count, rule_count)."""
    current_rules = parse_rules(rules_xml)
    baseline_rules = load_baseline(baseline_file)
    alerts = 0

    try:
        if baseline_rules is not None:
            # Baseline protection: don't overwrite a populated baseline with empty results
            if len(current_rules) == 0 and len(baseline_rules) > 0:
                print(f"  [{device_group}/{rulebase_label}] BASELINE ANOMALY: "
                      f"API returned 0 rules but baseline has {len(baseline_rules)}. "
                      f"Baseline preserved.")
                log_alert(alert_log, f"BASELINE_ANOMALY_{rulebase_label.upper()}",
                          {"name": f"{device_group}/{rulebase_label}"},
                          f"Device group '{device_group}' {rulebase_label}-rulebase returned 0 rules "
                          f"but baseline has {len(baseline_rules)}. "
                          f"Possible API error or misconfiguration. Baseline NOT overwritten.",
                          commit_ctx, device_group, tracker=tracker)
                return alerts, len(baseline_rules)

            added, removed, modified = diff_rules(baseline_rules, current_rules)

            if not added and not removed and not modified:
                pass  # no changes
            else:
                print(f"  [{device_group}/{rulebase_label}] "
                      f"+{len(added)} added, -{len(removed)} removed, ~{len(modified)} modified")

                alerts += _check_rule_list(added, "ADDED", cfg, ra_apps,
                                           service_objects, commit_ctx, device_group, alert_log, tracker, fs_apps)
                alerts += _check_rule_list(removed, "REMOVED", cfg, ra_apps,
                                           service_objects, commit_ctx, device_group, alert_log, tracker, fs_apps)

                for change in modified:
                    new_rule = change["new"]
                    old_rule = change["old"]
                    new_triggered, new_reason = should_alert(new_rule, cfg, ra_apps, service_objects, fs_apps=fs_apps)
                    old_triggered, old_reason = should_alert(old_rule, cfg, ra_apps, service_objects, fs_apps=fs_apps)
                    if new_triggered or old_triggered:
                        reason = new_reason or old_reason
                        diff_str = format_modified_diff(old_rule, new_rule)
                        log_alert(alert_log, alert_type_for(reason, "MODIFIED"), change,
                                  f"Rule '{new_rule['name']}' modified: {diff_str}. "
                                  f"Now: {new_rule['from']} -> {new_rule['to']}, "
                                  f"app={new_rule['application']}, service={new_rule.get('service', ['?'])}, "
                                  f"action={new_rule['action']}. Trigger: {reason}",
                                  commit_ctx, device_group, tracker=tracker)
                        alerts += 1
                    else:
                        log_info("Rule modified", new_rule, device_group)
        else:
            print(f"  [{device_group}/{rulebase_label}] First run — saving {len(current_rules)} rules as baseline")
    except Exception as e:
        print(f"  ERROR: Alert processing failed for {device_group}/{rulebase_label}: {e}",
              file=sys.stderr)

    # Save baseline (skip if anomaly was detected — handled above with early return)
    save_baseline(baseline_file, current_rules)

    return alerts, len(current_rules)


def _check_single_dg(dg, client, cfg, ra_apps, shared_services, commit_ctx,
                     data_dir, alert_log, tracker=None, fs_apps=None):
    """Check one device group (pre + post rulebase).
    Returns dict with alerts count and rule counts."""
    result = {"alerts": 0, "dg": dg, "pre_rules": 0, "post_rules": 0}

    # Merge shared + DG-specific service objects
    try:
        dg_services = client.get_service_objects(dg)
    except Exception as e:
        _dg_warn(dg, "services", e)
        dg_services = {}
    service_objects = {**shared_services, **dg_services}

    # Check pre-rulebase
    try:
        pre_xml = client.get_pre_rules(dg)
        pre_baseline = data_dir / "baselines" / f"{dg}_pre_baseline.json"
        alert_count, rule_count = _check_dg_rulebase(
            "pre", pre_xml, pre_baseline, cfg,
            ra_apps, service_objects, commit_ctx, dg, alert_log, tracker, fs_apps,
        )
        result["alerts"] += alert_count
        result["pre_rules"] = rule_count
        _dg_ok(dg, "pre")
    except Exception as e:
        _dg_warn(dg, "pre", e)

    # Check post-rulebase
    try:
        post_xml = client.get_post_rules(dg)
        post_baseline = data_dir / "baselines" / f"{dg}_post_baseline.json"
        alert_count, rule_count = _check_dg_rulebase(
            "post", post_xml, post_baseline, cfg,
            ra_apps, service_objects, commit_ctx, dg, alert_log, tracker, fs_apps,
        )
        result["alerts"] += alert_count
        result["post_rules"] = rule_count
        _dg_ok(dg, "post")
    except Exception as e:
        _dg_warn(dg, "post", e)

    return result


def run_check(cfg, client=None, tracker=None):
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
        fs_apps = client.get_file_sharing_apps()
        print(f"Loaded {len(fs_apps)} file-sharing apps")
    except Exception as e:
        print(f"WARNING: Could not fetch file-sharing apps: {e}")
        fs_apps = set()

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
        print(f"Recent commits by: {commit_ctx['changed_by']}")
    except Exception as e:
        print(f"WARNING: Could not fetch config log: {e}")
        commit_ctx = {}

    # Detect if this is a first run (no baselines exist yet)
    baseline_dir = data_dir / "baselines"
    is_first_run = not any(
        f.name.endswith("_baseline.json") and not f.name.startswith("remote_access")
        and not f.name.startswith("file-sharing")
        for f in baseline_dir.iterdir() if f.is_file()
    ) if baseline_dir.exists() else True

    # Check all device groups in parallel
    max_workers = cfg.get("max_workers", 10)
    total_alerts = 0
    dg_results = []

    print(f"Checking {len(device_groups)} device groups (max {max_workers} parallel)...")

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _check_single_dg, dg, client, cfg, ra_apps,
                shared_services, commit_ctx, data_dir, alert_log, tracker, fs_apps,
            ): dg
            for dg in device_groups
        }
        for future in as_completed(futures):
            dg = futures[future]
            try:
                result = future.result()
                total_alerts += result["alerts"]
                dg_results.append(result)
            except Exception as e:
                print(f"ERROR: Unexpected failure checking {dg}: {e}", file=sys.stderr)

    # First run summary — show empty vs populated so admin can verify
    if is_first_run and dg_results:
        empty_pre = sorted(r["dg"] for r in dg_results if r["pre_rules"] == 0)
        empty_post = sorted(r["dg"] for r in dg_results if r["post_rules"] == 0)
        populated_pre = sorted((r["dg"], r["pre_rules"]) for r in dg_results if r["pre_rules"] > 0)
        populated_post = sorted((r["dg"], r["post_rules"]) for r in dg_results if r["post_rules"] > 0)

        print(f"\n{'='*60}")
        print(f"FIRST RUN SUMMARY — Baselines created for {len(dg_results)} device groups")
        print(f"{'='*60}")

        if empty_pre:
            print(f"\nEmpty pre-rulebases ({len(empty_pre)}) — verify these are expected:")
            for dg in empty_pre:
                print(f"  {dg}/pre — 0 rules")

        if empty_post:
            print(f"\nEmpty post-rulebases ({len(empty_post)}) — verify these are expected:")
            for dg in empty_post:
                print(f"  {dg}/post — 0 rules")

        if populated_pre:
            print(f"\nPopulated pre-rulebases ({len(populated_pre)}):")
            for dg, count in populated_pre:
                print(f"  {dg}/pre — {count} rules")

        if populated_post:
            print(f"\nPopulated post-rulebases ({len(populated_post)}):")
            for dg, count in populated_post:
                print(f"  {dg}/post — {count} rules")

        print(f"{'='*60}\n")

    # Save check result for history
    _save_check_history(data_dir, len(device_groups), total_alerts, dg_results)

    # Report suppressed DGs
    suppressed = [k for k, v in _dg_failures.items() if v >= _SUPPRESS_AFTER]
    if suppressed:
        print(f"[SUPPRESSED] {len(suppressed)} DG/rulebase(s) consistently failing: "
              f"{', '.join(sorted(suppressed))}")

    print(f"\nCheck complete: {len(device_groups)} device groups, {total_alerts} new alerts")
    return total_alerts


def _save_check_history(data_dir, dg_count, alert_count, dg_results):
    """Append check result to history file for dashboard consumption."""
    history_file = data_dir / "logs" / "check_history.json"
    entry = {
        "timestamp": datetime.now().isoformat(),
        "device_groups": dg_count,
        "alerts": alert_count,
        "dg_summary": [
            {"dg": r["dg"], "pre": r["pre_rules"], "post": r["post_rules"], "alerts": r["alerts"]}
            for r in dg_results
        ],
    }
    history_file.parent.mkdir(parents=True, exist_ok=True)

    # Keep last 100 entries
    history = []
    if history_file.exists():
        try:
            with open(history_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        history.append(line)
        except Exception:
            pass

    history.append(json.dumps(entry))
    history = history[-100:]

    with open(history_file, "w") as f:
        f.write("\n".join(history) + "\n")
