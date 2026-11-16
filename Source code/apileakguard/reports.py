"""Masked reports, remediation guidance and safe exports."""
import csv
from html import escape
from io import StringIO
import json
from pathlib import Path
from tempfile import NamedTemporaryFile

from . import VERSION
from .model import InputError
from .policies import SEVERITIES


def prioritize(findings):
    return sorted(findings, key=lambda row: (SEVERITIES.index(row["severity"]),
                                            row["confidence"] != "confirmed", row["id"]))


def remediation(report):
    return [{"priority": i, "finding": item["id"], "endpoint": item["endpoint"], "field": item["field"],
             "rule": item["rule"], "reason": item["rationale"], "action": item["remedy"],
             "verification": item["verification"]}
            for i, item in enumerate(prioritize(report.get("findings", [])), 1)]


def atomic_write(destination, text, *, replace=False):
    destination = Path(destination)
    if destination.exists() and not replace:
        raise InputError("Export already exists. Confirm replacement and retry.")
    temp = None
    try:
        mode = {"mode": "wb"} if isinstance(text, bytes) else {"mode": "w", "encoding": "utf-8", "newline": ""}
        with NamedTemporaryFile(dir=destination.parent, delete=False, **mode) as stream:
            temp = Path(stream.name)
            stream.write(text)
        if replace:
            temp.replace(destination)
        else:
            # A hard link provides an atomic, exclusive create on the supported NTFS target.
            destination.hardlink_to(temp)
    except FileExistsError:
        raise InputError("Export already exists. Confirm replacement and retry.") from None
    except OSError:
        raise InputError("Could not write the selected export. Check the destination and file permissions.") from None
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)
    return destination


def csv_cell(value):
    value = str(value if value is not None else "")
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")) else value


def export(report, destination, *, replace=False):
    destination = Path(destination)
    suffix = destination.suffix.lower()
    if suffix == ".json":
        text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    elif suffix == ".csv":
        output = StringIO()
        writer = csv.writer(output)
        columns = ["section", "id", "severity", "confidence", "rule", "field", "source", "location",
                   "rationale", "remedy", "details"]
        writer.writerow(columns)
        def data_cell(row):
            return json.dumps(row, ensure_ascii=False, separators=(",", ":"))

        writer.writerow(["summary", report.get("run_id", ""), *[""] * 8, data_cell({
            key: report.get(key) for key in ("summary", "state", "version", "warnings", "input_fingerprint")
        })])
        for item in report.get("findings", []):
            writer.writerow(["finding", *(csv_cell(item.get(key)) for key in columns[1:-1]), data_cell(item)])
        for section in ("coverage", "policy_outcomes", "remediation", "candidates", "correlations"):
            for item in report.get(section, []):
                writer.writerow([section, *[""] * 9, data_cell(item)])
        text = output.getvalue()
    elif suffix == ".html":
        body = escape(json.dumps(report, ensure_ascii=False, indent=2))
        summary = f"{len(report.get('findings', []))} findings across {len(report.get('coverage', []))} evidence records"
        text = (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            '<title>APILeakGuard report</title><style>body{font:16px system-ui;margin:2rem auto;max-width:74rem;'
            'padding:0 1rem}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style></head>'
            f'<body><h1>APILeakGuard {VERSION}</h1><p>{summary}</p><pre>{body}</pre></body></html>'
        )
    else:
        raise InputError("Select an HTML, JSON or CSV report destination.")
    return atomic_write(destination, text, replace=replace)


def compare_policies(before, after):
    def violations(report):
        return {(tuple(row["endpoint"]), row["field"]) for row in report.get("findings", [])}

    previous, current = violations(before), violations(after)

    def fields(values):
        return [{"endpoint": endpoint, "field": field} for endpoint, field in sorted(values, key=repr)]

    return {"previous_version": before.get("policy_version"), "current_version": after.get("policy_version"),
            "new_violations": fields(current - previous), "continuing_violations": fields(current & previous),
            "violations_only_under_previous_policy": fields(previous - current)}


def compare_runs(before, after):
    old = {item["id"]: item for item in before.get("findings", [])}
    new = {item["id"]: item for item in after.get("findings", [])}
    by_endpoint = {}
    for row in after.get("coverage", []):
        if row["state"] == "observed":
            by_endpoint.setdefault(tuple(row["endpoint"]), []).append(row)
    comparable = before.get("ruleset") == after.get("ruleset") and before.get("policy_hash") == after.get("policy_hash")

    def verified(item):
        return comparable and any(item["rule"] not in row["skipped"]
                                  for row in by_endpoint.get(tuple(item["endpoint"]), []))

    return {"before": before.get("run_id"), "after": after.get("run_id"),
            "new": sorted(new.keys() - old.keys()), "recurring": sorted(old.keys() & new.keys()),
            "resolved": sorted(key for key in old.keys() - new.keys() if verified(old[key])),
            "coverage_gaps": sorted(key for key in old.keys() - new.keys() if not verified(old[key]))}
