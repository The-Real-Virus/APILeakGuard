"""Validated optional field policies, independent of the built-in scanner."""
from datetime import date
from fnmatch import fnmatchcase

from .detection import Rule, finding
from .importers import read_document
from .model import InputError, field_paths, fingerprint
from .privacy import mask, mask_text

SCOPE_FIELDS = ("project", "api", "environment", "method", "route", "status", "role")
SEVERITIES = ("critical", "high", "medium", "low", "info")


def validate(data):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise InputError("Policy schema_version must be 1.")
    if not isinstance(data.get("version"), str) or not data["version"].strip():
        raise InputError("Policy version must be a nonempty string.")
    rules = data.get("rules")
    if not isinstance(rules, list) or len(rules) > 500:
        raise InputError("Policy rules must be a list of up to 500 rules.")
    seen = set()
    for i, rule in enumerate(rules, 1):
        if not isinstance(rule, dict):
            raise InputError(f"Rule {i} must be an object.")
        identifier = rule.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in seen:
            raise InputError(f"Rule {i} needs a unique text ID.")
        seen.add(identifier)
        scope = rule.get("scope", {})
        if not isinstance(scope, dict) or set(scope) - set(SCOPE_FIELDS) or any(
                type(x) not in {int, str} for x in scope.values()):
            raise InputError(f"Rule {i} contains an invalid scope.")
        for key in ("allow", "forbid"):
            values = rule.get(key, [])
            if not isinstance(values, list) or any(not isinstance(x, str) or not x for x in values):
                raise InputError(f"Rule {i} {key} must contain text field patterns.")
        if not rule.get("allow") and not rule.get("forbid"):
            raise InputError(f"Rule {i} must specify allowed or forbidden fields.")
        if rule.get("severity", "high") not in SEVERITIES:
            raise InputError(f"Rule {i} severity is invalid.")
        for exception in rule.get("exceptions", []):
            if not isinstance(exception, dict) or not all(
                isinstance(exception.get(key), str) and exception[key].strip()
                for key in ("field", "reason", "expires")
            ):
                raise InputError(f"Rule {i} exception requires field, reason and expiry.")
            try:
                date.fromisoformat(exception["expires"])
            except ValueError:
                raise InputError(f"Rule {i} exception expiry must be YYYY-MM-DD.") from None
            if "severity" in exception and exception["severity"] not in SEVERITIES:
                raise InputError(f"Rule {i} exception severity is invalid.")
    return data


def load_policy(path):
    return validate(read_document(path)[0])


def matches(path, pattern):
    # Evidence uses literal [] for array elements; escape those before glob matching.
    return fnmatchcase(path, pattern.replace("[]", "[[]]"))


def compare(record, policy, today=None, known=()):
    today = today or date.today()
    outcomes = []
    applicable = []
    identity = {"policy_version": mask_text(policy["version"], known), "policy_hash": fingerprint(policy),
                "source_id": record.source_id}
    for rule in policy["rules"]:
        scope = rule.get("scope", {})
        route = record.template or record.route
        values = {key: getattr(record, key) for key in SCOPE_FIELDS} | {"route": route}
        row = {**identity, "rule": mask_text(rule["id"], known)}
        if any(values[key] is not None and str(values[key]) != str(value) for key, value in scope.items()):
            outcomes.append({**row, "status": "not applicable"})
            continue
        unknown = [key for key in scope if values[key] is None]
        if unknown or record.kind != "response" or not record.observed or record.body_state != "parsed":
            outcomes.append({**row, "status": "unevaluated", "missing": unknown or ["parsed response"]})
            continue
        applicable.append(rule)
        outcomes.append({**row, "status": "matched"})
    findings = []
    for path, _, value in field_paths(record.body):
        candidates = []
        for rule in applicable:
            forbidden = any(matches(path, pattern) for pattern in rule.get("forbid", []))
            allowed = rule.get("allow", [])
            allowed_path = any(matches(path, pattern) or pattern.startswith(path + ".") or
                               pattern.startswith(path + "[]") for pattern in allowed)
            if forbidden or allowed:
                candidates.append((len(rule.get("scope", {})), forbidden, rule["id"],
                                   forbidden or not allowed_path, rule))
        if not candidates:
            continue
        _, _, _, violation, rule = sorted(candidates, key=lambda row: (-row[0], -row[1], row[2]))[0]
        if not violation:
            continue
        status, severity = "violation", rule.get("severity", "high")
        details = {}
        for exception in rule.get("exceptions", []):
            if not matches(path, exception["field"]):
                continue
            if date.fromisoformat(exception["expires"]) < today:
                outcomes.append({**identity, "rule": mask_text(rule["id"], known), "status": "expired exception",
                                 "field": mask_text(path, known), "exception": mask(exception, known)})
                continue
            details["exception"] = mask(exception, known)
            if "severity" in exception:
                severity = exception["severity"]
            else:
                status = "excepted"
            break
        outcomes.append({**identity, **details, "rule": mask_text(rule["id"], known),
                         "status": status, "field": mask_text(path, known)})
        if status == "violation":
            meta = Rule(severity, "An observed field violates the selected field policy.",
                        "Limit the response fields for this role and repeat the same test.")
            findings.append(finding(record, mask_text(f"policy:{rule['id']}", known), path, rule=meta, known=known))
    return findings, outcomes
