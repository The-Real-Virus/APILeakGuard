"""Centralized masking for evidence, diagnostics and provider context."""
import re
from urllib.parse import urlsplit

MASK = "[REDACTED]"
SECRET_FIELD = re.compile(
    r"password|passwd|secret|token|authorization|api[-_ ]?key|private[-_ ]?key|"
    r"credential|session[-_ ]?(?:id|key)?",
    re.I,
)
PERSON_FIELD = re.compile(
    r"tax[-_ ]?id|social[-_ ]?security|^ssn$|email|phone|^address$|"
    r"^full[-_ ]?name$|birth[-_ ]?date|card[-_ ]?number|bank[-_ ]?account|^iban$|^cvv$",
    re.I,
)
DEBUG_FIELD = re.compile(r"stack[-_ ]?trace|^traceback$|^internal|debug[-_ ]?(?:info|detail|trace)|^sql$", re.I)
CREDENTIAL = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)|"
    r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/\-=]{8,}|\b(?:AIza[A-Za-z0-9_-]{35}|"
    r"sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[0-9A-Za-z_]{20,}|"
    r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,})\b",
    re.I,
)
EMAIL = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", re.I)
TAX_ID = re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")
DEBUG = re.compile(r"Traceback \(most recent call last\):|(?:[A-Z]:\\|/)(?:home|users|var/log|srv|app)[\\/][^\s\"']+|"
                   r"\bat [\w.$]+\([^()\r\n]+:\d+\)", re.I)
ASSIGNMENT = re.compile(
    r"(?P<key>[\w-]*(?:secret|password|token|api[-_ ]?key|authorization|tax[-_ ]?id|"
    r"ssn|card[-_ ]?number|email|phone)[\w-]*[\"']?\s*[:=]\s*)"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;&}\]]+)", re.I,
)
URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
PLACEHOLDER = re.compile(r"^(?:\s*|none|null|test|password|placeholder|changeme|example|"
                         r"<[^<>]+>|\{\{[^{}]+\}\}|\[REDACTED\])$", re.I)


def supplied(value):
    return isinstance(value, (str, int, float)) and not isinstance(value, bool) and not PLACEHOLDER.fullmatch(str(value))


def mask_url(value):
    try:
        parts = urlsplit(value)
        host = parts.netloc.rsplit("@", 1)[-1]
        if not host:
            return MASK
        path = mask_text(parts.path, urls=False)
        return f"{parts.scheme}://{host}{path}" + (f"?{MASK}" if parts.query else "")
    except ValueError:
        return MASK


def mask_text(value, known=(), *, urls=True):
    for secret in sorted({part for part in known if part}, key=len, reverse=True):
        value = value.replace(secret, MASK)
    if urls:
        value = URL.sub(lambda m: mask_url(m[0]), value)
    for pattern in CREDENTIAL, EMAIL, TAX_ID, CARD, DEBUG:
        value = pattern.sub(MASK, value)
    return ASSIGNMENT.sub(lambda m: m["key"] + MASK, value)


def mask(value, known=(), *, depth=0):
    if depth > 40:
        return MASK
    if isinstance(value, dict):
        return {
            mask_text(str(key), known): MASK if item is not None and
            (SECRET_FIELD.search(str(key)) or PERSON_FIELD.search(str(key)) or DEBUG_FIELD.search(str(key)))
            else mask(item, known, depth=depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [mask(item, known, depth=depth + 1) for item in value]
    return mask_text(value, known) if isinstance(value, str) else value


def mask_headers(headers, known=()):
    result = []
    for name, value in headers:
        lower = name.lower()
        if lower in {"cookie", "set-cookie"}:
            pieces = value.split(";")
            if lower == "set-cookie":
                cookie_name = pieces[0].partition("=")[0]
                value = mask_text(cookie_name, known) + "=" + MASK
                for attr in pieces[1:]:
                    key, sep, data = attr.strip().partition("=")
                    if key.lower() in {"secure", "httponly", "partitioned"} and not sep:
                        value += f"; {key}"
                    elif key.lower() == "samesite" and data.lower() in {"strict", "lax", "none"}:
                        value += f"; {key}={data}"
            else:
                value = "; ".join(mask_text(part.strip().partition("=")[0], known) + "=" + MASK for part in pieces)
        elif SECRET_FIELD.search(lower) or PERSON_FIELD.search(lower):
            value = MASK
        else:
            value = mask_text(value, known)
        result.append([mask_text(name, known), value])
    return result
