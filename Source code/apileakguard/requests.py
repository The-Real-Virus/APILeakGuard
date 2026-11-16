"""HTTP runner for fixed, explicitly approved functional suites."""
from base64 import b64encode
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from http.cookiejar import CookieJar
from ipaddress import IPv4Address, IPv4Network
import json
from queue import Queue
import re
import socket
import ssl
from threading import Event
from time import monotonic
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, ProxyHandler, Request, build_opener

from .model import BODY_BYTES, Evidence, InputError, fingerprint, header_value, parse_body
from .privacy import PERSON_FIELD, SECRET_FIELD, mask, mask_headers, mask_url

METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
RETRYABLE = {"GET", "HEAD", "OPTIONS"}
MAX_REQUESTS = 200
VARIABLE = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_.-]*)\}\}")
HEADER = re.compile(r"^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$")
RESTRICTED_HEADERS = {"host", "content-length", "transfer-encoding", "proxy-authorization",
                      "authorization", "cookie", "connection"}
LOCAL = {"127.0.0.1", "::1", "localhost"}
PRIVATE_NETWORKS = tuple(IPv4Network(prefix) for prefix in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def private_lab_address(host):
    try:
        address = IPv4Address(host)
    except ValueError:
        return False
    return any(address in network for network in PRIVATE_NETWORKS)


def safe_path(path):
    if re.search(r"%(?:2e|2f|5c|25)", path, re.I) or "\\" in path:
        raise InputError("Ambiguous encoded or escaped API path.")
    decoded = unquote(path, errors="strict")
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise InputError("Dot segments are prohibited in API paths.")
    if any(ord(char) <= 32 or ord(char) == 127 for char in decoded):
        raise InputError("Invalid whitespace or control character in API path.")
    return decoded or "/"


def url_parts(url, allow_private_http=False):
    try:
        if not isinstance(url, str) or any(ord(char) <= 32 or ord(char) == 127 for char in url):
            raise ValueError
        parsed = urlsplit(url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname or "\\" in parsed.netloc:
            raise InputError("Enter a full endpoint URL such as https://api.example.com/orders.")
        if parsed.username is not None or parsed.password is not None:
            raise InputError("Remove credentials from the URL and use the Authentication field.")
        if parsed.fragment:
            raise InputError("Remove the part beginning with #. Use the endpoint URL from your API documentation.")
        if parsed.scheme == "http" and parsed.hostname.lower() not in LOCAL and not (
                allow_private_http and private_lab_address(parsed.hostname)):
            raise InputError("Use HTTPS for this host. A literal private lab IP can use anonymous HTTP.")
        if parsed.port == 0:
            raise ValueError
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed, (parsed.scheme, parsed.hostname.lower(), port), safe_path(parsed.path)
    except InputError:
        raise
    except (ValueError, UnicodeError):
        raise InputError("Check the endpoint URL for a valid host, port, and path.") from None


def endpoint_text(value):
    value = value.strip()
    for scheme in ("http", "https"):
        if value.lower().startswith(scheme + "\\://"):
            return scheme + "://" + value[len(scheme) + 4:]
    return value


def private_http_target(url):
    try:
        parsed = urlsplit(url)
        return parsed.scheme == "http" and private_lab_address(parsed.hostname or "")
    except ValueError:
        return False


def operation_from_url(url):
    """Create a single GET from an endpoint explicitly entered by the user."""
    target = endpoint_text(url)
    lab = private_http_target(target)
    parsed, _, _ = url_parts(target, lab)
    operation = {"api": parsed.hostname, "method": "GET", "base": f"{parsed.scheme}://{parsed.netloc}/",
                 "path": target}
    if lab:
        operation["allow_private_http"] = True
    return operation


@dataclass(frozen=True)
class Scope:
    base: str
    allow_private_http: bool = False

    def check(self, url):
        base, origin, base_path = url_parts(self.base, self.allow_private_http)
        _, actual, path = url_parts(url, self.allow_private_http)
        base_path = base_path.rstrip("/")
        if base.query or origin != actual or not (path == base_path or path.startswith(base_path + "/")):
            raise InputError("The destination is outside the approved API origin or base path.")
        return url


def operation_scope(operation):
    return Scope(operation["base"], operation.get("allow_private_http") is True)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def substitute(value, variables, *, encode=False):
    if isinstance(value, str):
        def resolve(match):
            name = match.group(1)
            if name not in variables:
                raise InputError(f"Missing variable {name}. Supply it before running the suite.")
            return quote(str(variables[name]), safe="") if encode else str(variables[name])
        return VARIABLE.sub(resolve, value)
    if isinstance(value, list):
        return [substitute(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, variables) for key, item in value.items()}
    return value


def scope_key(suite, operation):
    return (suite.get("project", "default"), operation.get("api", "api"),
            operation.get("environment", "test"), operation.get("profile") or "unauthenticated")


def validate_suite(suite):
    if not isinstance(suite, dict) or suite.get("schema_version") != 1:
        raise InputError("Suite schema_version must be 1.")
    operations = suite.get("operations")
    if not isinstance(operations, list) or not 1 <= len(operations) <= MAX_REQUESTS:
        raise InputError("A suite needs 1–200 selected operations.")
    variables = suite.get("variables", {})
    if not isinstance(variables, dict) or any(SECRET_FIELD.search(str(key)) for key in variables):
        raise InputError("Store secret values in an authentication profile.")
    for i, item in enumerate(operations, 1):
        if not isinstance(item, dict) or item.get("method") not in METHODS:
            raise InputError(f"Operation {i} needs a supported HTTP method.")
        if item["method"] not in RETRYABLE and item.get("approve_mutation") is not True:
            raise InputError(f"Operation {i} needs explicit approval for a state-changing method.")
        lab = item.get("allow_private_http") is True
        url_parts(item.get("base"), lab)
        if lab and (item["method"] not in {"GET", "HEAD"} or item.get("profile") or item.get("body") is not None
                    or item.get("headers") or item.get("query") or item.get("capture")):
            raise InputError("This private lab URL uses plain HTTP. Choose No authentication and send a GET or HEAD "
                             "without custom headers, query fields, or a body. Use HTTPS to send a Bearer token.")
        target = item.get("path")
        if not isinstance(target, str) or not target.strip() or target.startswith("//"):
            raise InputError(f"Operation {i} needs a path or approved URL.")
        if lab and "?" in target:
            raise InputError("Private lab HTTP does not send query strings.")
        if "://" in target:
            if VARIABLE.search(urlsplit(target).netloc):
                raise InputError("Destination origins must be fixed at approval time.")
            operation_scope(item).check(VARIABLE.sub("preview", target))
        else:
            effective_url(item, {name: "preview" for name in VARIABLE.findall(target)})
        for name in ("headers", "query", "expect", "capture", "response_schemas"):
            if not isinstance(item.get(name, {}), dict):
                raise InputError(f"Operation {i} {name} must be an object.")
        for key in item.get("headers", {}):
            if key.lower() in RESTRICTED_HEADERS or SECRET_FIELD.search(key) or not HEADER.fullmatch(key):
                raise InputError(f"Operation {i} contains a restricted header name.")
        for name, minimum, limit, default in (("timeout", 1, 30, 8), ("retries", 0, 2, 0)):
            value = item.get(name, default)
            if type(value) is not int or not minimum <= value <= limit:
                raise InputError(f"Operation {i} {name} must be between {minimum} and {limit}.")
        if item.get("retries") and item["method"] not in RETRYABLE:
            raise InputError("Retries are available only for GET, HEAD and OPTIONS.")
    return suite


def effective_url(operation, variables):
    scope = operation_scope(operation)
    path = substitute(operation["path"], variables, encode=True)
    if "://" not in path:
        if path.startswith("/"):
            base = urlsplit(scope.base)
            path = f"{base.scheme}://{base.netloc}{path}"
        else:
            path = urljoin(scope.base.rstrip("/") + "/", path)
    return scope.check(path)


def preview(suite):
    validate_suite(suite)
    rows = []
    for item in suite["operations"]:
        placeholders = VARIABLE.findall(json.dumps(item, ensure_ascii=True))
        supplied = suite.get("variables", {})
        values = {name: "pending-input" for name in placeholders} | supplied
        target = mask_url(effective_url(item, values))
        rows.append({"method": item["method"], "destination": target, "api": item.get("api", "api"),
                     "environment": item.get("environment", "test"),
                     "profile": item.get("profile", "unauthenticated"),
                     "state_changing": item["method"] not in RETRYABLE,
                     "private_lab_http": item.get("allow_private_http") is True,
                     "source": mask(item.get("source", "selected operation")),
                     "required_inputs": sorted(set(placeholders) - supplied.keys()),
                     "variables": mask({name: supplied[name] for name in set(placeholders) & supplied.keys()}),
                     "query_parameters": sorted(item.get("query", {})),
                     "headers": mask_headers(list(item.get("headers", {}).items())),
                     "body": mask(item.get("body"))})
    return {"suite_fingerprint": fingerprint(suite), "request_count": len(rows), "operations": rows}


def lookup(body, path):
    value = body
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            return False, None
        value = value[key]
    return True, value


def assertions(operation, record):
    expected = operation.get("expect", {})
    result = {}
    if "status" in expected:
        result["status"] = record.status == expected["status"]
    if "content_type" in expected:
        result["content_type"] = record.media_type.split(";")[0].lower() == str(expected["content_type"]).lower()
    for name, value in expected.get("headers", {}).items():
        result[f"header {name}"] = header_value(record.headers, name) == value
    for path, value in expected.get("fields", {}).items():
        exists, actual = lookup(record.body, path)
        result[f"field {path}"] = exists and value == actual
    for path in expected.get("forbid", []):
        result[f"absent {path}"] = not lookup(record.body, path)[0]
    if record.schema is not None:
        from jsonschema import Draft202012Validator, SchemaError
        from referencing import Registry
        from referencing.exceptions import Unresolvable
        try:
            Draft202012Validator.check_schema(record.schema)
            result["schema"] = record.body_state == "parsed" and Draft202012Validator(
                record.schema, registry=Registry()).is_valid(record.body)
        except (SchemaError, Unresolvable, TypeError, ValueError):
            result["schema"] = False
    return result


def attach_credential(secret, headers, known):
    known.add(secret.value)
    if "\r" in secret.value or "\n" in secret.value:
        raise InputError("Authentication value contains a prohibited line break.")
    if secret.kind == "basic":
        known.update(part for part in secret.value.split(":", 1) if part)
        encoded = b64encode(secret.value.encode("utf-8")).decode("ascii")
        known.add(encoded)
        headers["Authorization"] = "Basic " + encoded
    elif secret.kind == "bearer":
        headers["Authorization"] = "Bearer " + secret.value
    elif secret.kind == "key":
        if not HEADER.fullmatch(secret.name) or secret.name.lower() in RESTRICTED_HEADERS:
            raise InputError("Choose a valid API key header.")
        headers[secret.name] = secret.value
    elif secret.kind == "cookie":
        headers["Cookie"] = secret.value
        known.update(part.partition("=")[2] for part in secret.value.split(";") if "=" in part)
    else:
        raise InputError("This credential cannot be used for API requests.")


def send(suite, operation, variables, secrets, opener, cancel, ordinal):
    url = effective_url(operation, variables)
    query = substitute(operation.get("query", {}), variables)
    if query:
        url += ("&" if "?" in url else "?") + urlencode(query, doseq=True)
    operation_scope(operation).check(url)
    request_headers = {name: str(substitute(value, variables))
                       for name, value in operation.get("headers", {}).items()}
    if any("\r" in value or "\n" in value for value in request_headers.values()):
        raise InputError("Request header contains a prohibited line break.")
    known = set()
    for handler in opener.handlers:
        if isinstance(handler, HTTPCookieProcessor):
            known.update(cookie.value for cookie in handler.cookiejar if cookie.value)
    profile = operation.get("profile")
    if profile:
        attach_credential(secrets.get(("api", *scope_key(suite, operation))), request_headers, known)
    body = substitute(operation.get("body"), variables)
    request_payload = body
    if operation.get("encoding") == "form":
        if not isinstance(body, dict):
            raise InputError("Form bodies must be objects.")
        body = urlencode(body, doseq=True).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif body is not None and (not isinstance(body, str) or operation.get("encoding") == "json"):
        body = json.dumps(body, ensure_ascii=True).encode("ascii")
        request_headers.setdefault("Content-Type", "application/json")
    elif isinstance(body, str):
        body = body.encode("utf-8")
    if body is not None and len(body) > BODY_BYTES:
        raise InputError("Request body exceeds the 2 MiB limit.")
    request = Request(url, data=body, headers=request_headers, method=operation["method"])
    timeout = operation.get("timeout", 8)
    retries = operation.get("retries", 0)
    start = monotonic()
    for attempt in range(retries + 1):
        if cancel.is_set():
            raise InputError("Cancelled before sending.")
        try:
            response = opener.open(request, timeout=timeout)
        except HTTPError as error:
            response = error
        except (OSError, URLError, ValueError) as error:
            if attempt < retries and not cancel.wait(0.25 * (attempt + 1)):
                continue
            reason = error.reason if isinstance(error, URLError) else error
            if isinstance(reason, TimeoutError):
                message = "The server did not respond before the timeout. Check that it is running and reachable from this PC."
            elif isinstance(reason, ssl.SSLError):
                message = "HTTPS verification failed. Check the host name and its TLS certificate."
            elif isinstance(reason, socket.gaierror):
                message = "The host name could not be resolved. Check the URL and connection."
            elif isinstance(reason, ConnectionRefusedError):
                message = "The host refused the connection. Check the server and port."
            else:
                message = "Could not reach the endpoint. Check the host, port, and connection."
            raise InputError(message) from None
        with response:
            status = response.code
            pairs = list(response.headers.items())
            known.update(value.split(";", 1)[0].partition("=")[2]
                         for name, value in pairs if name.lower() == "set-cookie" and "=" in value)
            content = bytearray()
            try:
                while len(content) <= BODY_BYTES and monotonic() - start < timeout and not cancel.is_set():
                    part = response.read1(min(65536, BODY_BYTES + 1 - len(content)))
                    if not part:
                        break
                    content.extend(part)
                else:
                    content = None
            except OSError:
                content = None
            media = header_value(pairs, "Content-Type")
            original = None
            if content is None:
                data, state = None, "clipped"
            else:
                try:
                    original = content.decode("utf-8")
                    data, state = parse_body(original, media)
                except UnicodeError:
                    data, state = None, "undecodable"
        break
    project, api, environment, _ = scope_key(suite, operation)
    route = urlsplit(url).path or "/"
    record = Evidence("response", "approved suite", f"operation {ordinal}", api, environment,
                      project=project, role=operation.get("role"), method=operation["method"], route=route,
                      status=status, media_type=media, headers=pairs, body=data, body_state=state,
                      source_id=fingerprint([fingerprint(suite), ordinal])[:24],
                      source_fingerprint=fingerprint(suite), template=operation.get("template"),
                      variant=operation.get("variant"), schema=operation.get("response_schemas", {}).get(
                          f"{status} {media.split(';', 1)[0].lower().strip()}", operation.get("schema")),
                      auth="failed" if status in {401, 403} else (profile or "unauthenticated"),
                      elapsed_ms=int((monotonic() - start) * 1000),
                      request_id=header_value(pairs, "X-Request-ID") or None,
                      request={"method": operation["method"], "destination": mask_url(url),
                               "headers": list(mask_headers(list(request_headers.items()), known)),
                               "body": mask(request_payload, known)},
                      original_text=original)
    record.expectations = assertions(operation, record)
    return record, known


def execute(suite, approved, secrets, cancel=None):
    validate_suite(suite)
    if approved != fingerprint(suite):
        raise InputError("Preview and approve this exact suite before sending.")
    cancel = cancel or Event()
    groups = defaultdict(list)
    for index, operation in enumerate(suite["operations"], 1):
        groups[scope_key(suite, operation)[:3]].append((index, operation))

    events = Queue()

    def run_group(operations):
        variables = dict(suite.get("variables", {}))
        openers = {}
        stopped = False
        for ordinal, operation in operations:
            if cancel.is_set() or stopped:
                events.put((ordinal, None, set(), "Cancelled." if cancel.is_set() else "Stopped after assertion failure."))
                continue
            lab = operation.get("allow_private_http") is True
            key = (*scope_key(suite, operation), operation.get("role"), operation["base"], lab)
            try:
                if key not in openers:
                    handlers = [ProxyHandler({}), NoRedirect()]
                    if not lab:
                        handlers.append(HTTPCookieProcessor(CookieJar()))
                    openers[key] = build_opener(*handlers)
                record, known = send(suite, operation, variables, secrets, openers[key], cancel, ordinal)
                stopped = operation.get("stop_on_failure", False) and not all(record.expectations.values())
                for name, path in operation.get("capture", {}).items():
                    found, value = lookup(record.body, path)
                    if found and isinstance(value, (str, int, bool, float)) and not (
                            SECRET_FIELD.search(name) or SECRET_FIELD.search(path) or PERSON_FIELD.search(path)
                            or mask(value, known) != value):
                        variables[name] = value
                events.put((ordinal, record, known, None))
            except InputError as error:
                events.put((ordinal, None, set(), str(error)))
            except (AttributeError, OSError, TypeError, ValueError):
                events.put((ordinal, None, set(), "Operation failed. Check scope, inputs and local TLS initialization."))

    def finished(_future):
        events.put(None)

    with ThreadPoolExecutor(max_workers=3) as queue:
        futures = [queue.submit(run_group, group) for group in groups.values()]
        for future in futures:
            future.add_done_callback(finished)
        remaining = len(futures)
        try:
            while remaining:
                item = events.get()
                if item is None:
                    remaining -= 1
                else:
                    yield item
            for future in futures:
                future.result()
        finally:
            if remaining:
                cancel.set()
