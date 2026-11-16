"""Deterministic checks over observed response and log evidence."""
from dataclasses import asdict, dataclass

from . import RULESET_VERSION
from .model import field_paths, fingerprint, header_value
from .privacy import (CREDENTIAL, DEBUG, DEBUG_FIELD, EMAIL, PERSON_FIELD, SECRET_FIELD,
                      TAX_ID, mask_text, supplied)


@dataclass(frozen=True)
class Rule:
    severity: str
    rationale: str
    remedy: str


RULES = {
    "credential": Rule("critical", "A credential-like value appeared in ordinary evidence.",
                       "Remove the value from the response or log and ask its owner to rotate it."),
    "personal": Rule("high", "The field or value may contain personal or financial data.",
                     "Select the fields required by this role and mask or omit the rest."),
    "internal": Rule("medium", "The evidence contains internal fields or debugging details.",
                      "Return a safe error and keep diagnostics in access-controlled logs."),
    "schema": Rule("high", "The response contains a field forbidden by its response schema.",
                   "Select permitted response fields explicitly and validate the response shape."),
    "cache": Rule("high", "Sensitive content was observed with shared-cache directives.",
                  "Set a private or no-store cache policy appropriate to the endpoint."),
    "cookie": Rule("medium", "An observed session cookie lacks Secure or HttpOnly.",
                   "Set Secure and HttpOnly on session cookies and review SameSite."),
    "content_type": Rule("low", "A structured response body lacks a JSON content type.",
                         "Return the declared content type and review nosniff behavior."),
    "cors": Rule("medium", "Wildcard CORS and the credentials directive occur together.",
                 "Review the intended origins and send explicit allowlisted origins for credentialed requests."),
}


def finding(record, rule_id, path, *, confidence="confirmed", rule=None, known=()):
    rule = rule or RULES[rule_id]
    endpoint = [mask_text(x, known) if isinstance(x, str) else x for x in record.endpoint_key()]
    safe_path = mask_text(path, known)
    return {
        **asdict(rule), "id": fingerprint([endpoint, rule_id, safe_path])[:24],
        "rule": rule_id, "ruleset": RULESET_VERSION, "endpoint": endpoint, "field": safe_path,
        "evidence": "[REDACTED]", "confidence": confidence,
        "source": mask_text(record.source, known), "source_id": record.source_id,
        "location": mask_text(record.location, known),
        "verification": "Repeat the same operation and response variant for the same role. Review the updated evidence.",
        "coverage": "observed",
    }


def schema_extras(schema, value, path=""):
    if isinstance(schema, dict) and isinstance(value, dict):
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return
        for key, item in value.items():
            child = f"{path}.{key}" if path else key
            if key in properties:
                yield from schema_extras(properties[key], item, child)
            elif schema.get("additionalProperties") is False:
                yield child
    elif isinstance(schema, dict) and isinstance(value, list) and isinstance(schema.get("items"), dict):
        for item in value:
            yield from schema_extras(schema["items"], item, path + "[]")


def scan(record, known=()):
    findings = {}
    skipped = {}

    def add(rule_id, path, confidence="confirmed"):
        item = finding(record, rule_id, path, confidence=confidence, known=known)
        findings[item["id"]] = item

    if not record.observed:
        return [], dict.fromkeys(RULES, "No observed response or log.")
    if record.body_state in {"missing", "clipped"}:
        skipped.update(dict.fromkeys(("credential", "personal", "internal"), "Body unavailable; inspected headers."))
    for path, key, value in field_paths(record.body):
        if supplied(value):
            if SECRET_FIELD.search(key):
                add("credential", path, "confirmed" if CREDENTIAL.search(str(value)) else "suspected")
            if PERSON_FIELD.search(key):
                add("personal", path, "suspected")
            if DEBUG_FIELD.search(key):
                add("internal", path)
    values = [(path, value) for path, _, value in field_paths(record.body) if isinstance(value, str)]
    if isinstance(record.body, str):
        values.append(("body", record.body))
    for key, value in record.headers:
        if key.lower() not in {"cookie", "set-cookie"}:
            values.append((f"header.{key}", value))
            if SECRET_FIELD.search(key) and supplied(value):
                add("credential", f"header.{key}", "suspected")
    for path, value in values:
        if CREDENTIAL.search(value) or any(secret and secret in value for secret in known):
            add("credential", path)
        if EMAIL.search(value) or TAX_ID.search(value):
            add("personal", path, "suspected")
        if DEBUG.search(value):
            add("internal", path)
    if record.schema is None or record.body_state != "parsed":
        skipped["schema"] = "A comparable response schema and parsed body are required."
    else:
        for path in schema_extras(record.schema, record.body):
            add("schema", path)
    if record.kind == "log":
        skipped.update(dict.fromkeys(("cache", "cookie", "content_type", "cors"), "HTTP response required."))
    else:
        cache = header_value(record.headers, "cache-control").lower()
        if ("public" in cache or "s-maxage=" in cache) and "no-store" not in cache and any(
                row["rule"] in {"credential", "personal"} for row in findings.values()):
            add("cache", "header.cache-control")
        for key, value in record.headers:
            if key.lower() == "set-cookie":
                name = value.partition("=")[0]
                attributes = {part.strip().partition("=")[0].lower() for part in value.split(";")[1:]}
                if SECRET_FIELD.search(name) and not {"secure", "httponly"} <= attributes:
                    add("cookie", f"header.set-cookie.{name}")
        if isinstance(record.body, (dict, list)) and "json" not in record.media_type.lower():
            add("content_type", "header.content-type")
        if header_value(record.headers, "access-control-allow-origin").strip() == "*" and \
                header_value(record.headers, "access-control-allow-credentials").lower() == "true":
            add("cors", "header.access-control-allow-origin", "suspected")
    return list(findings.values()), skipped
