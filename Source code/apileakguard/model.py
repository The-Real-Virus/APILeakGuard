"""Native evidence records and bounded parsing primitives."""
from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
from math import isfinite
from pathlib import Path

from . import SCHEMA_VERSION
from .privacy import mask, mask_headers, mask_text

FILE_BYTES = 8 * 1024 * 1024
BODY_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 5000
MAX_DEPTH = 32
PARSER_VERSION = "1.0"


class InputError(ValueError):
    """An input or operation that could not be processed safely."""


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def fingerprint(value):
    return sha256(canonical(value).encode("utf-8")).hexdigest()


def bounded(data, depth=0, remaining=None):
    if remaining is None:
        remaining = [250000]
    remaining[0] -= 1
    if depth > MAX_DEPTH or remaining[0] < 0:
        raise InputError("Input exceeds the structural limits.")
    if isinstance(data, dict):
        for key, value in data.items():
            if not isinstance(key, str):
                raise InputError("Object keys must be text.")
            bounded(value, depth + 1, remaining)
    elif isinstance(data, list):
        for value in data:
            bounded(value, depth + 1, remaining)
    elif isinstance(data, float) and not isfinite(data):
        raise InputError("Non-finite number in document.")
    elif data is not None and not isinstance(data, (int, float, bool, str)):
        raise InputError("The document contains an unsupported value.")


def parse_json(text):
    def invalid(_value):
        raise InputError("Non-finite number in JSON.")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InputError("Duplicate field name in JSON.")
            result[key] = value
        return result

    try:
        result = json.loads(text, object_pairs_hook=unique, parse_constant=invalid)
    except json.JSONDecodeError as error:
        raise InputError(f"Invalid JSON at line {error.lineno}, column {error.colno}.") from None
    except (ValueError, RecursionError):
        raise InputError("Invalid JSON or structural limit exceeded.") from None
    bounded(result)
    return result


def read_input(path):
    path = Path(path)
    if not local_path(path):
        raise InputError("Select a local file on this computer.")
    if not path.is_file():
        raise InputError("Select a regular input file.")
    with path.open("rb") as stream:
        data = stream.read(FILE_BYTES + 1)
    if len(data) > FILE_BYTES:
        raise InputError("File exceeds the 8 MiB import limit.")
    try:
        return data.decode("utf-8-sig"), sha256(data).hexdigest()
    except UnicodeError:
        raise InputError("Use UTF-8 input.") from None


def local_path(path):
    path = Path(path)
    if str(path).startswith(("\\\\", "//")):
        return False
    if __import__("os").name == "nt":
        import ctypes
        resolved = path.absolute()
        if resolved.drive and ctypes.windll.kernel32.GetDriveTypeW(str(Path(resolved.anchor))) == 4:
            return False
        if path.exists() and str(path.resolve()).startswith(("\\\\", "//")):
            return False
    return True


def headers(value):
    if isinstance(value, dict):
        return [(str(key), str(item)) for key, item in value.items()]
    if isinstance(value, list):
        result = []
        for item in value:
            if isinstance(item, dict) and item.get("disabled") is not True:
                result.append((str(item.get("name", item.get("key", ""))), str(item.get("value", ""))))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                result.append((str(item[0]), str(item[1])))
        return result
    return []


def header_value(pairs, name):
    return next((value for key, value in pairs if key.lower() == name.lower()), "")


def parse_body(value, media_type="", *, present=True):
    if not present:
        return None, "missing"
    if value == "":
        return "", "empty"
    if isinstance(value, str) and len(value.encode("utf-8")) > BODY_BYTES:
        return None, "clipped"
    if isinstance(value, str) and ("json" in media_type.lower() or value.lstrip().startswith(("{", "["))):
        try:
            return parse_json(value), "parsed"
        except InputError:
            return value, "malformed"
    return value, "parsed"


@dataclass
class Evidence:
    kind: str
    source: str
    location: str
    api: str
    environment: str
    project: str = "default"
    role: str | None = None
    method: str | None = None
    route: str | None = None
    status: int | None = None
    media_type: str = ""
    headers: list = field(default_factory=list)
    body: object = None
    body_state: str = "missing"
    source_id: str = ""
    source_fingerprint: str = ""
    request_id: str | None = None
    timestamp: str | None = None
    template: str | None = None
    variant: str | None = None
    auth: str = "unknown"
    elapsed_ms: int | None = None
    schema: dict | bool | None = None
    expectations: dict = field(default_factory=dict)
    request: dict | None = None
    links: list[str] = field(default_factory=list)
    original_text: str | None = field(default=None, repr=False)
    parser_version: str = PARSER_VERSION
    schema_version: int = SCHEMA_VERSION

    @property
    def observed(self):
        return self.kind == "log" or (self.kind == "response" and self.status is not None)

    def safe(self, known=()):
        value = asdict(self)
        original = value.pop("original_text")
        response_headers = value.pop("headers")
        request = value.pop("request")
        value.pop("links")
        safe = {key: mask(item, known) for key, item in value.items()}
        safe["headers"] = mask_headers(response_headers, known)
        if request is not None:
            request_headers = request.pop("headers", [])
            safe["request"] = mask(request, known)
            safe["request"]["headers"] = mask_headers(request_headers, known)
        if original and isinstance(self.body, str):
            safe["raw_text"] = mask_text(original, known)
        return safe

    def endpoint_key(self):
        return [self.project, self.api, self.environment, self.method, self.template or self.route,
                self.role, self.status, self.variant]


def field_paths(value, prefix=""):
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else key
            yield path, key, item
            yield from field_paths(item, path)
    elif isinstance(value, list):
        for item in value:
            yield from field_paths(item, prefix + "[]")
