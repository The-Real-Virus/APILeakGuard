"""Bounded local adapters for selected captures, contracts and collections."""
from base64 import b64decode
from binascii import Error as Base64Error
import csv
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from urllib.parse import urlsplit

from .model import (BODY_BYTES, MAX_RECORDS, Evidence, InputError, bounded, fingerprint,
                    header_value, headers, parse_body, parse_json, read_input)
from .privacy import SECRET_FIELD, mask_text


@dataclass
class ImportResult:
    format: str
    records: list[Evidence] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    variables: list[str] = field(default_factory=list)


def read_document(path):
    text, digest = read_input(path)
    if Path(path).suffix.lower() not in {".yaml", ".yml"}:
        return parse_json(text), digest
    try:
        import yaml
    except ImportError:
        raise InputError("YAML support requires the locked PyYAML dependency.") from None
    try:
        count = 0
        depth = 0
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            count += 1
            if isinstance(event, (yaml.SequenceStartEvent, yaml.MappingStartEvent)):
                depth += 1
            elif isinstance(event, (yaml.SequenceEndEvent, yaml.MappingEndEvent)):
                depth -= 1
            if isinstance(event, yaml.AliasEvent) or count > 250000 or depth > 32:
                raise InputError("YAML aliases or structural limits are unsupported.")
        data = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, TypeError, ValueError):
        raise InputError("Invalid or unsupported YAML document.") from None
    bounded(data)
    return data, digest


def object_or_empty(value):
    return value if isinstance(value, dict) else {}


def list_or_empty(value):
    return value if isinstance(value, list) else []


def route_of(url):
    if isinstance(url, dict):
        url = url.get("raw", "")
    if not isinstance(url, str) or not url:
        return None
    try:
        return urlsplit(url).path or "/"
    except ValueError:
        return None


class Context:
    def __init__(self, source, digest, mapping):
        self.source = source
        self.digest = digest
        self.mapping = mapping

    def evidence(self, location, data, *, kind="response"):
        data = object_or_empty(data)
        response_headers = headers(data.get("headers"))
        media = str(data.get("media_type") or header_value(response_headers, "Content-Type"))
        body, state = parse_body(data.get("body"), media, present="body" in data)
        state = data["body_state"] if data.get("body_state") in {"missing", "clipped", "undecodable"} else state
        status = data.get("status")
        if isinstance(status, str) and status.isdecimal() and len(status) == 3:
            status = int(status)
        if type(status) is not int or not 100 <= status <= 599:
            status = None
        original_url = data.get("url")
        if isinstance(original_url, dict):
            original_url = original_url.get("raw")
        body_text = data.get("body")
        return Evidence(
            kind, self.source, location, str(data.get("api") or self.mapping.get("api") or "import"),
            str(data.get("environment") or self.mapping.get("environment") or "unspecified"),
            project=str(self.mapping.get("project") or data.get("project") or "default"),
            role=data.get("role") or self.mapping.get("role"),
            method=str(data["method"]).upper() if data.get("method") else None,
            route=route_of(data.get("route") or data.get("url") or self.mapping.get("route")),
            status=status, media_type=media, headers=response_headers, body=body, body_state=state,
            source_id=fingerprint([self.digest, location])[:24], source_fingerprint=self.digest,
            request_id=str(data["request_id"]) if data.get("request_id") is not None else None,
            timestamp=str(data["timestamp"]) if data.get("timestamp") is not None else None,
            template=data.get("template"), variant=data.get("variant"), schema=data.get("schema"),
            links=[original_url] if kind == "request" and isinstance(original_url, str) else [],
            original_text=body_text if isinstance(body_text, str) and state not in {"missing", "clipped"} else None,
        )


def request_data(request):
    request = object_or_empty(request)
    return {key: request[key] for key in ("method", "url", "headers", "body", "role") if key in request}


def postman(data, context):
    if not str(data.get("info", {}).get("schema", "")).endswith("/v2.1.0/collection.json"):
        raise InputError("Select a Postman Collection v2.1 export.")
    result = ImportResult("Postman Collection v2.1",
                          warnings=["Scripts and imported authentication are inert. Review request templates before use."])

    def items(group, location):
        for index, item in enumerate(list_or_empty(group)):
            if not isinstance(item, dict):
                continue
            path = f"{location}/{index}"
            if "item" in item:
                items(item["item"], path + "/item")
            if "request" not in item:
                continue
            request = request_data(item["request"])
            request["headers"] = object_or_empty(item["request"]).get("header", [])
            result.records.append(context.evidence(path + "/request", request, kind="request"))
            for response_index, response in enumerate(list_or_empty(item.get("response"))):
                if not isinstance(response, dict):
                    continue
                fields = {**request, **request_data(response.get("originalRequest")),
                          "status": response.get("code"), "headers": response.get("header", [])}
                if "body" in response:
                    fields["body"] = response["body"]
                else:
                    fields.pop("body", None)
                result.records.append(context.evidence(f"{path}/response/{response_index}", fields))

    items(data.get("item"), "/item")
    return result


def newman(data, context):
    entries = object_or_empty(data.get("run")).get("executions")
    if not isinstance(entries, list):
        raise InputError("Unsupported Newman JSON report. Use run.executions.")
    result = ImportResult("Newman JSON")
    for index, row in enumerate(entries):
        row = object_or_empty(row)
        response = object_or_empty(row.get("response"))
        fields = request_data(row.get("request"))
        fields.pop("body", None)
        fields.update(status=response.get("code"), headers=response.get("header", []))
        if "body" in response:
            fields["body"] = response["body"]
        elif isinstance(response.get("stream"), dict):
            values = response["stream"].get("data")
            if isinstance(values, list) and len(values) <= BODY_BYTES:
                try:
                    fields["body"] = bytes(values).decode("utf-8")
                except (ValueError, TypeError, UnicodeError):
                    fields["body_state"] = "undecodable"
        if not response:
            result.warnings.append(f"Execution {index + 1} lacks a response.")
        result.records.append(context.evidence(f"/run/executions/{index}", fields,
                                               kind="response" if response else "request"))
    return result


def har(data, context):
    log = object_or_empty(data.get("log"))
    if log.get("version") != "1.2":
        raise InputError("Select a HAR 1.2 capture.")
    result = ImportResult("HAR 1.2")
    for index, row in enumerate(list_or_empty(log.get("entries"))):
        row = object_or_empty(row)
        request, response = request_data(row.get("request")), object_or_empty(row.get("response"))
        request.pop("body", None)
        content = object_or_empty(response.get("content"))
        fields = {**request, "headers": response.get("headers"), "status": response.get("status"),
                  "timestamp": row.get("startedDateTime"), "media_type": content.get("mimeType")}
        if "text" in content:
            fields["body"] = content["text"]
            if content.get("encoding") == "base64":
                fields.pop("body")
                try:
                    if len(content["text"]) > BODY_BYTES * 2:
                        fields["body_state"] = "clipped"
                    else:
                        fields["body"] = b64decode(content["text"], validate=True).decode("utf-8")
                except (TypeError, ValueError, Base64Error, UnicodeError):
                    fields["body_state"] = "undecodable"
        result.records.append(context.evidence(f"/log/entries/{index}", fields))
    return result


HTTP_METHODS = {"get", "head", "options", "post", "put", "patch", "delete", "trace"}


def openapi(data, context, local_documents):
    version = str(data.get("openapi"))
    if not version.startswith(("3.0.", "3.1.")):
        raise InputError("Select an OpenAPI 3.0 or 3.1 document.")
    result = ImportResult(f"OpenAPI {version}")
    documents = {"": data, **local_documents}
    unsupported = {"allOf", "oneOf", "anyOf", "$dynamicRef", "unevaluatedProperties", "patternProperties"}

    available = [250000]

    def resolve(node, document="", seen=()):
        available[0] -= 1
        if available[0] < 0:
            raise InputError("OpenAPI reference expansion exceeded the structural limit.")
        if len(seen) > 12:
            return {}
        if isinstance(node, list):
            return [resolve(item, document, seen) for item in node]
        if not isinstance(node, dict):
            return node
        for key in unsupported.intersection(node):
            result.warnings.append(f"Schema feature {key} needs review.")
        if "$ref" in node:
            ref = str(node["$ref"])
            name, _, pointer = ref.partition("#")
            name = name or document
            key = (name, pointer)
            if name not in documents or key in seen or (pointer and not pointer.startswith("/")):
                result.warnings.append("Remote, unselected or recursive reference skipped.")
                return {}
            value = documents[name]
            for token in pointer.split("/")[1:]:
                value = object_or_empty(value).get(token.replace("~1", "/").replace("~0", "~"))
            if value is None:
                result.warnings.append("Unresolved local reference skipped.")
                return {}
            return resolve(value, name, seen + (key,))
        return {key: resolve(item, document, seen) for key, item in node.items()}

    for route, methods in object_or_empty(data.get("paths")).items():
        for method, operation in object_or_empty(resolve(methods)).items():
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            location = f"/paths/{route}/{method}"
            request = {"method": method, "route": route, "template": route}
            result.records.append(context.evidence(location, request, kind="request"))
            for code, response in object_or_empty(operation.get("responses")).items():
                for media, info in object_or_empty(object_or_empty(response).get("content")).items():
                    info = object_or_empty(info)
                    examples = {key: value.get("value") for key, value in object_or_empty(info.get("examples")).items()
                                if isinstance(value, dict) and "value" in value}
                    if "example" in info:
                        examples["example"] = info["example"]
                    for variant, value in examples.items():
                        fields = {**request, "status": code, "body": value, "media_type": media,
                                  "schema": info.get("schema"), "variant": variant}
                        # Documented examples contribute coverage context. They are not observed responses.
                        result.records.append(context.evidence(f"{location}/responses/{code}/{variant}",
                                                               fields, kind="example"))
                    if not examples and "schema" in info:
                        schema = {**request, "status": code, "media_type": media, "schema": info["schema"]}
                        result.records.append(context.evidence(f"{location}/responses/{code}/schema", schema,
                                                               kind="example"))
    return result


def insomnia(data, context):
    version = data.get("__export_format")
    if version != 4 or not isinstance(data.get("resources"), list):
        raise InputError("Supported Insomnia JSON exports use __export_format 4 and resources.")
    result = ImportResult("Insomnia JSON v4", warnings=["Imported authentication and scripts are inert."])
    for index, row in enumerate(data["resources"]):
        row = object_or_empty(row)
        if row.get("_type") == "request":
            result.records.append(context.evidence(f"/resources/{index}", request_data(row), kind="request"))
        if row.get("_type") == "environment":
            result.variables.extend(mask_text(key) for key in object_or_empty(row.get("data")))
    return result


def native(rows, context, input_format):
    result = ImportResult(input_format)
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            result.warnings.append(f"Record {index} is not an object.")
            continue
        if row.get("schema_version", 1) != 1:
            result.warnings.append(f"Record {index} uses an unsupported native schema version.")
            continue
        kind = row.get("kind") or ("response" if "status" in row else "log")
        if kind not in {"response", "request", "log", "example"}:
            result.warnings.append(f"Record {index} has an unsupported record type.")
            continue
        if kind == "log" and "body" not in row:
            row = {**row, "body": row}
        result.records.append(context.evidence(f"record {index}", row, kind=kind))
    return result


def import_file(path, mapping=None, *, local_references=()):
    path = Path(path)
    mapping = mapping or {}
    suffix = path.suffix.lower()
    text, digest = read_input(path)
    context = Context(mask_text(path.name), digest, mapping)
    if suffix == ".ndjson":
        rows = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            if len(rows) >= MAX_RECORDS:
                raise InputError("Input exceeds the record limit.")
            try:
                rows.append(parse_json(line))
            except InputError:
                raise InputError(f"Invalid NDJSON at line {number}.") from None
        result = native(rows, context, "NDJSON")
    elif suffix == ".csv":
        columns = mapping.get("columns")
        if not isinstance(columns, dict) or not columns:
            raise InputError("Supply a CSV column mapping before import.")
        reader = csv.DictReader(StringIO(text))
        if not set(columns.values()) <= set(reader.fieldnames or ()):
            raise InputError("CSV mapping refers to a missing column.")
        rows = []
        try:
            for row in reader:
                if len(rows) >= MAX_RECORDS:
                    raise InputError("Input exceeds the record limit.")
                rows.append({key: row.get(column) for key, column in columns.items()})
        except csv.Error:
            raise InputError("Invalid or oversize CSV field.") from None
        result = native(rows, context, "CSV")
    elif suffix in {".json", ".har", ".yaml", ".yml"}:
        data = read_document(path)[0] if suffix in {".yaml", ".yml"} else parse_json(text)
        if isinstance(data, list):
            result = native(data, context, "JSON records")
        elif not isinstance(data, dict):
            raise InputError("Select a supported evidence object or record list.")
        elif "openapi" in data:
            selected = tuple(local_references or mapping.get("local_references", ()))
            names = [Path(ref).name for ref in selected]
            if len(selected) > 16 or len({name.casefold() for name in names}) != len(names):
                raise InputError("Choose up to 16 local schema reference files with distinct names.")
            references = {name: read_document(ref)[0] for name, ref in zip(names, selected)}
            result = openapi(data, context, references)
        elif "info" in data and "item" in data:
            result = postman(data, context)
        elif data.get("_postman_variable_scope") in {"environment", "globals"}:
            result = ImportResult("Postman variables", warnings=["Variable values were excluded."])
            result.variables = [mask_text(str(row.get("key"))) for row in list_or_empty(data.get("values"))
                                if isinstance(row, dict) and row.get("key") and not SECRET_FIELD.search(str(row["key"]))]
        elif "run" in data:
            result = newman(data, context)
        elif "log" in data and isinstance(data["log"], dict) and "entries" in data["log"]:
            result = har(data, context)
        elif "__export_format" in data:
            result = insomnia(data, context)
        else:
            rows = data.get("records", [data])
            if not isinstance(rows, list):
                raise InputError("Native records must be a list.")
            result = native(rows, context, "JSON evidence")
    else:
        raise InputError("Unsupported input format. Select JSON, YAML, NDJSON, HAR or mapped CSV.")
    if len(result.records) > MAX_RECORDS:
        raise InputError("Input exceeds the record limit.")
    result.warnings = list(dict.fromkeys(result.warnings))[:100]
    return result
