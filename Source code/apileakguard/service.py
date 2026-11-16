"""Application service shared by the desktop, CLI and assistant."""
from dataclasses import fields
from collections import defaultdict
from pathlib import Path
from threading import Event
from urllib.parse import urlsplit

from . import RULESET_VERSION, VERSION
from .credentials import MemorySecrets
from .detection import scan
from .importers import import_file, read_document
from .model import MAX_RECORDS, Evidence, InputError, fingerprint, local_path
from .policies import compare
from .privacy import MASK, URL, mask, mask_text, mask_url
from .reports import export, prioritize, remediation
from .requests import Scope, execute, preview, private_http_target, url_parts, validate_suite
from .storage import Store


INPUT_EXTENSIONS = {".json", ".yaml", ".yml", ".har", ".ndjson", ".csv"}

def selected_files(paths):
    files = []
    for value in paths:
        path = Path(value)
        if not local_path(path):
            raise InputError("Select an input on a local drive.")
        if path.is_dir():
            for index, entry in enumerate(path.iterdir()):
                if index >= 2000:
                    raise InputError("Folder contains too many entries. Select a smaller folder.")
                if entry.suffix.lower() in INPUT_EXTENSIONS and entry.is_file() and not entry.is_symlink():
                    files.append(entry)
        else:
            files.append(path)
    files = sorted(set(files))
    if not 1 <= len(files) <= 100:
        raise InputError("Select 1–100 supported files.")
    return files


def prepare_definitions(paths, scopes, mapping=None, cancel=None, *, only_route=None):
    """Prepare fixed ordinary requests from reviewed definitions and owner-supplied scopes."""
    if not isinstance(scopes, dict) or not scopes or any(not isinstance(value, str) for value in scopes.values()):
        raise InputError("Supply approved base URLs keyed by API, file name, or default.")
    if only_route is not None and (not only_route.startswith("/") or only_route.startswith("//")
                                   or any(character in only_route for character in "?#{}\\")):
        raise InputError("Enter a documented endpoint path such as /workshop/api/shop/products.")
    operations = []
    for path in selected_files(paths):
        if cancel and cancel.is_set():
            raise InputError("Plan preparation cancelled.")
        imported = import_file(path, mapping)
        documented = defaultdict(dict)
        for example in imported.records:
            if example.kind == "example" and example.status and isinstance(example.schema, (dict, bool)):
                key = f"{example.status} {example.media_type.lower()}"
                documented[(example.method, example.route)][key] = example.schema
        for record in imported.records:
            if record.kind != "request" or record.method not in {"GET", "HEAD", "OPTIONS"}:
                continue
            route = record.route or "/"
            if only_route is not None and route != only_route:
                continue
            base = scopes.get(path.name) or scopes.get(record.api) or scopes.get("default")
            if base is None:
                raise InputError(f"Supply an approved base URL for {mask_text(path.name)}.")
            lab = private_http_target(base)
            if lab and only_route is None:
                raise InputError("Choose one documented GET or HEAD path when preparing a private HTTP lab plan.")
            if lab and record.method == "OPTIONS":
                continue
            if "{{" not in route:
                route = route.replace("{", "{{").replace("}", "}}")
            operation = {"api": record.api, "role": record.role, "environment": record.environment,
                         "method": record.method, "base": base, "path": route, "source": mask_text(path.name)}
            if lab:
                operation["allow_private_http"] = True
            schemas = documented.get((record.method, record.route))
            if schemas:
                operation["response_schemas"] = schemas
            operations.append(operation)
    if only_route is not None and not operations:
        raise InputError("No matching read-only operation appears in the selected definitions. Check the exact path and method.")
    suite = {"schema_version": 1, "operations": operations}
    return validate_suite(suite)


class Workspace:
    def __init__(self, root, secrets=None):
        self.root = Path(root)
        self.store = Store(self.root / "workspace.sqlite")
        self.store.recover_orphans()
        self.secrets = secrets or MemorySecrets()
        self.output = self.root / "reports"
        self.output.mkdir(exist_ok=True)

    def inspect_inputs(self, paths, mapping=None):
        rows = []
        for path in selected_files(paths):
            try:
                result = import_file(path, mapping)
            except InputError as error:
                rows.append({"file": mask_text(path.name), "error": str(error)})
            except (OSError, ValueError, TypeError, AttributeError, OverflowError):
                rows.append({"file": mask_text(path.name), "error": "Invalid input structure or inaccessible file."})
            else:
                rows.append({"file": mask_text(path.name), "format": result.format,
                             "records": len(result.records), "warnings": result.warnings,
                             "variables": result.variables})
        return rows

    def approved(self, suite):
        key = "suite:" + fingerprint(suite)
        return self.store.get_value("settings", key, False) is True

    def save_project(self, project):
        if not isinstance(project, dict) or project.get("schema_version") != 1 or not isinstance(project.get("name"), str):
            raise InputError("Provide a named project with schema_version 1.")
        name = project["name"].strip()
        scopes = project.get("scopes")
        if not name or len(name) > 100 or not isinstance(scopes, list) or not 1 <= len(scopes) <= 100:
            raise InputError("Provide a project name and 1–100 scopes.")
        keys = set()
        for row in scopes:
            if not isinstance(row, dict) or any(not isinstance(row.get(key), str) or not row[key].strip()
                                               for key in ("api", "environment", "base")):
                raise InputError("Each scope needs an API, environment and base URL.")
            key = (row["api"], row["environment"])
            if key in keys:
                raise InputError("An API and environment can have only one selected scope in a project.")
            keys.add(key)
            if url_parts(row["base"])[0].query:
                raise InputError("Do not include query parameters in an approved base URL.")
        if mask(project) != project:
            raise InputError("Use project metadata without credential or personal values.")
        self.store.set_value("settings", "project:" + name, project)

    def project_scopes(self, suite):
        name = suite.get("project", "default")
        project = self.store.get_value("settings", "project:" + name)
        if project is None:
            return
        scopes = {(row["api"], row["environment"]): Scope(row["base"]) for row in project["scopes"]}
        for operation in suite["operations"]:
            pair = (operation.get("api", "api"), operation.get("environment", "test"))
            if pair not in scopes:
                raise InputError("The selected project has no approved scope for this API and environment.")
            scopes[pair].check(operation["base"])

    def save_suite(self, name, suite):
        name = name.strip()
        if not name or len(name) > 100:
            raise InputError("Enter a suite name of 1–100 characters.")
        validate_suite(suite)
        if mask(suite) != suite:
            raise InputError("Save credential references and synthetic test inputs in suites.")
        self.store.set_value("settings", "saved-suite:" + name, suite)

    def approve(self, suite, expected):
        result = preview(suite)
        self.project_scopes(suite)
        if result["suite_fingerprint"] != expected:
            raise InputError("Suite changed after preview. Review the current request plan.")
        self.store.set_value("settings", "suite:" + expected, True)
        return expected

    def start(self):
        identifier = self.store.create()
        payload = {"version": VERSION, "report_schema": 1, "ruleset": RULESET_VERSION,
                   "records": [], "coverage": [], "findings": [], "candidates": [],
                   "warnings": [], "policy_outcomes": [], "policy_hash": None, "remediation": []}
        self.store.update(identifier, "running", payload)
        return identifier, payload

    def add(self, payload, record, known=(), policy=None):
        if len(payload["records"]) >= MAX_RECORDS:
            raise InputError("Run exceeds the 5,000 record limit.")
        safe = record.safe(known)
        findings, skipped = scan(record, known)
        if policy:
            violations, outcomes = compare(record, policy, known=known)
            findings.extend(violations)
            payload["policy_outcomes"].extend(outcomes)
            for row in outcomes:
                if row["status"] == "unevaluated":
                    skipped["policy:" + row["rule"]] = "Missing comparable policy inputs."
        payload["records"].append(safe)
        payload["findings"].extend(findings)
        state = "observed"
        if record.auth == "failed":
            state = "authentication failed"
        elif not record.observed:
            state = "missing response"
        elif record.body_state in {"clipped", "malformed", "undecodable"}:
            state = "partial"
        assumptions = {mask_text(key, known): bool(value) for key, value in record.expectations.items()}
        payload["coverage"].append({
            "endpoint": [safe[key] for key in ("project", "api", "environment", "method")] +
                        [safe["template"] or safe["route"], safe["role"], safe["status"], safe["variant"]],
            "state": state, "auth": safe["auth"], "assertions": assumptions, "source_id": safe["source_id"],
            "skipped": skipped,
        })
        existing = {item["id"] for item in payload["candidates"]}
        for candidate in discovered_links(record, known):
            if candidate["id"] not in existing and len(existing) < 1000:
                payload["candidates"].append(candidate)
                existing.add(candidate["id"])

    def finish(self, identifier, payload, state):
        payload["findings"] = prioritize({item["id"]: item for item in payload["findings"]}.values())
        payload["remediation"] = remediation(payload)
        payload["correlations"] = correlate(payload["records"])
        payload["input_fingerprint"] = fingerprint([record["source_fingerprint"] for record in payload["records"]])
        payload["summary"] = {"coverage": len(payload["coverage"]), "findings": len(payload["findings"]),
                              "candidates_pending": len(payload["candidates"]),
                              "assertion_failures": sum(not all(row.get("assertions", {}).values())
                                                        for row in payload["coverage"])}
        self.store.update(identifier, state, payload)
        report = self.store.get(identifier)
        try:
            export(report, self.output / f"{identifier}.json")
        except InputError:
            payload["warnings"].append("Automatic report export failed. Export again from the stored run.")
            self.store.update(identifier, "incomplete", payload)
            report = self.store.get(identifier)
        return report

    def _imports(self, payload, paths, mapping, policy, cancel):
        for path in selected_files(paths):
            if cancel.is_set():
                break
            try:
                result = import_file(path, mapping)
            except InputError as error:
                payload["warnings"].append(f"{mask_text(path.name)}: {error}")
                continue
            except (OSError, ValueError, TypeError, AttributeError, OverflowError):
                payload["warnings"].append(f"{mask_text(path.name)}: Invalid structure or unreadable input.")
                continue
            for record in result.records:
                if cancel.is_set():
                    break
                self.add(payload, record, policy=policy)
            payload["warnings"].extend(result.warnings)

    def analyze(self, paths, mapping=None, policy=None, cancel=None):
        selected_files(paths)
        cancel = cancel or Event()
        identifier, payload = self.start()
        if policy:
            payload["policy_hash"] = fingerprint(policy)
        state = "finished"
        try:
            self._imports(payload, paths, mapping, policy, cancel)
        except InputError as error:
            payload["warnings"].append(str(error))
            state = "incomplete"
        if cancel.is_set():
            state = "cancelled"
        elif not any(row["state"] == "observed" for row in payload["coverage"]):
            state = "incomplete"
        return self.finish(identifier, payload, state)

    def run(self, suite, *, policy=None, paths=(), mapping=None, cancel=None, progress=None, secrets=None):
        validate_suite(suite)
        self.project_scopes(suite)
        digest = fingerprint(suite)
        if not self.approved(suite):
            raise InputError("Preview and approve this exact suite before running.")
        cancel = cancel or Event()
        identifier, payload = self.start()
        payload["suite_fingerprint"] = digest
        if policy:
            payload["policy_hash"] = fingerprint(policy)
        state = "finished"
        try:
            registry = self.secrets if secrets is None else secrets
            for ordinal, record, known, error in execute(suite, digest, registry, cancel):
                if record:
                    self.add(payload, record, known, policy)
                elif error:
                    payload["coverage"].append({"operation": ordinal, "endpoint": [], "state": "skipped",
                                                "skipped": {}, "reason": mask_text(error)})
                    state = "incomplete"
                self.store.update(identifier, "running", payload)
                if progress:
                    progress(len(payload["coverage"]))
            if paths and not cancel.is_set():
                self._imports(payload, paths, mapping, policy, cancel)
        except InputError as error:
            payload["warnings"].append(str(error))
            state = "incomplete"
        if cancel.is_set():
            state = "cancelled"
        elif any(row["state"] != "observed" for row in payload["coverage"]):
            state = "incomplete"
        return self.finish(identifier, payload, state)

    def policy_report(self, run_id, policy):
        report = self.store.get(run_id)
        outcomes = []
        findings = []
        accepted = {item.name for item in fields(Evidence)}
        for row in report.get("records", []):
            record = Evidence(**{key: value for key, value in row.items() if key in accepted})
            violations, checks = compare(record, policy)
            outcomes.extend(checks)
            findings.extend(violations)
        result = {**report, "findings": prioritize(findings), "policy_outcomes": outcomes,
                  "policy_hash": fingerprint(policy), "policy_version": mask_text(policy["version"])}
        result["remediation"] = remediation(result)
        return result


def discovered_links(record, known=()):
    values = list(record.links)
    if not record.observed and not values:
        return []
    for name, value in record.headers:
        if name.lower() in {"link", "location"}:
            values.extend(match[0] for match in URL.finditer(value))
    if isinstance(record.body, (dict, list, str)):
        import json
        values.extend(match[0] for match in URL.finditer(json.dumps(record.body, ensure_ascii=False)))
    candidates = []
    for value in values[:100]:
        target = mask_text(mask_url(value), known, urls=False)
        try:
            parts = urlsplit(target)
        except ValueError:
            continue
        if not parts.hostname:
            continue
        key = fingerprint([record.project, record.environment, target])[:24]
        candidates.append({"id": key, "destination": target, "source_id": record.source_id,
                           "source": mask_text(record.source), "origin": f"{parts.scheme}://{parts.netloc}",
                           "status": "pending review"})
    return candidates


def correlate(records):
    groups = defaultdict(list)
    for record in records:
        request_id = record.get("request_id")
        if request_id and MASK not in request_id:
            groups[(record["project"], record["api"], record["environment"], request_id)].append(record)
    correlations = []
    for (_project, _api, _env, request_id), group in groups.items():
        responses = sum(record["kind"] == "response" for record in group)
        logs = sum(record["kind"] == "log" for record in group)
        status = "ambiguous" if responses > 1 else ("matched" if responses == 1 and logs else "missing related record")
        correlations.append({"request_id": request_id, "status": status,
                             "sources": [record["source_id"] for record in group]})
    return correlations


def load_suite(path):
    return validate_suite(read_document(path)[0])


def result_exit(report, fail_on="high"):
    if report["state"] != "finished":
        return 3
    if report.get("summary", {}).get("assertion_failures"):
        return 2
    severities = ["critical", "high", "medium", "low", "info"]
    if fail_on != "never":
        threshold = severities.index(fail_on)
        if any(severities.index(item["severity"]) <= threshold for item in report.get("findings", [])):
            return 2
    return 0
