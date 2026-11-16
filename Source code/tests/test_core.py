from datetime import date
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
from threading import Event
import unittest
from unittest.mock import patch

from apileakguard.detection import RULES, scan
from apileakguard.fixes import apply_patch, preview_patch, rollback
from apileakguard.importers import import_file
from apileakguard.model import Evidence, InputError, parse_json
from apileakguard.policies import compare, load_policy, validate
from apileakguard.privacy import MASK
from apileakguard.reports import compare_policies, compare_runs, csv_cell, export
from apileakguard.service import Workspace, correlate, prepare_definitions, result_exit
from apileakguard.storage import Store

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def record(body, headers=(), schema=None, media="application/json"):
    return Evidence("response", "synthetic.json", "record 1", "fixture", "test",
                    method="GET", route="/customers/1", status=200, role="support",
                    body=body, body_state="parsed", headers=list(headers), schema=schema, media_type=media)


class CoreTests(unittest.TestCase):
    def test_rule_fixtures(self):
        schema = {"properties": {"safe": {"type": "string"}}, "additionalProperties": False}
        positives = {
            "credential": record({"password": "synthetic-value"}),
            "personal": record({"email": "sample@example.test"}),
            "internal": record({"stackTrace": "synthetic debug"}),
            "schema": record({"extra": True}, schema=schema),
            "cache": record({"email": "sample@example.test"}, [("Cache-Control", "public")]),
            "cookie": record({}, [("Set-Cookie", "sessionid=fake; SameSite=Lax")]),
            "content_type": record({}, media="text/plain"),
            "cors": record({}, [("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")]),
        }
        clean = record({"safe": "yes"}, [("Set-Cookie", "sessionid=fake; Secure; HttpOnly")], schema=schema)
        negative, skipped = scan(clean)
        self.assertEqual(negative, [])
        self.assertEqual(skipped, {})
        self.assertEqual(positives.keys(), RULES.keys())
        for rule, evidence in positives.items():
            with self.subTest(rule=rule):
                hits, _ = scan(evidence)
                self.assertIn(rule, {item["rule"] for item in hits})
                self.assertEqual(hits, scan(evidence)[0])
                self.assertTrue(all(item["evidence"] == MASK for item in hits))
        self.assertEqual(scan(record({}))[1].keys(), {"schema"})

    def test_policy_precedence_and_exception_expiry(self):
        evidence = record({"customer": {"taxId": "999-99-0000"}})
        policy = {"schema_version": 1, "version": "demo", "rules": [
            {"id": "all", "forbid": ["customer.taxId"]},
            {"id": "support", "scope": {"role": "support"}, "forbid": ["customer.taxId"],
             "exceptions": [{"field": "customer.taxId", "reason": "Synthetic evaluation", "expires": "2025-04-01"}]},
        ]}
        policy = validate(policy)
        self.assertFalse(compare(evidence, policy, date(2025, 4, 1))[0])
        findings, outcomes = compare(evidence, policy, date(2025, 4, 2))
        self.assertEqual([item["rule"] for item in findings], ["policy:support"])
        self.assertIn("expired exception", [item["status"] for item in outcomes])
        evidence.role = None
        self.assertIn("unevaluated", [item["status"] for item in compare(evidence, policy)[1]])

    def test_offline_scan_export_and_fix(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(socket.socket, "connect", side_effect=AssertionError):
            root = Path(folder)
            target = root / "example.json"
            target.write_bytes((FIXTURES / "support-exposed.json").read_bytes())
            workspace = Workspace(root / "profile")
            policy = load_policy(FIXTURES / "support-policy.json")
            before = workspace.analyze([target], policy=policy)
            self.assertEqual(result_exit(before), 2)
            self.assertEqual(len(before["findings"]), 2)
            self.assertNotIn("999-99-0000", json.dumps(before))
            self.assertNotIn("999-99-0000", workspace.store.path.read_bytes().decode("ascii", errors="ignore"))
            self.assertEqual(len(workspace.store.search(before["run_id"], "taxId")), 1)
            self.assertEqual(len(workspace.store.search(before["run_id"], "taxId role:support status:200")), 1)
            self.assertEqual(workspace.store.search(before["run_id"], "taxId role:manager"), [])
            for extension in ("html", "csv", "json"):
                destination = root / f"report.{extension}"
                export(before, destination)
                self.assertNotIn("999-99-0000", destination.read_text("utf-8"))
                with self.assertRaises(InputError):
                    export(before, destination)
            html = root / "escaped.html"
            export({"unsafe": "<script>alert(1)</script>"}, html)
            self.assertNotIn("<script>", html.read_text("utf-8"))
            self.assertEqual(csv_cell("  =2+2"), "'  =2+2")
            change = preview_patch(root, target.name, "body.customer.taxId")
            self.assertIn('taxId', change.diff)
            self.assertNotIn("999-99-0000", change.diff)
            backup = apply_patch(change, root / "backups")
            self.assertNotIn(b"999-99-0000", backup.read_bytes())
            after = workspace.analyze([target], policy=policy)
            self.assertEqual(result_exit(after), 0)
            self.assertEqual(len(compare_runs(before, after)["resolved"]), 2)
            rollback(change, backup)
            self.assertEqual(result_exit(workspace.analyze([target], policy=policy)), 2)
            self.assertEqual(len(workspace.policy_report(before["run_id"], policy)["findings"]), 1)
            strict = workspace.policy_report(before["run_id"], policy)
            relaxed = workspace.policy_report(before["run_id"], load_policy(FIXTURES / "support-policy-relaxed.json"))
            delta = compare_policies(strict, relaxed)
            self.assertEqual(delta["violations_only_under_previous_policy"][0]["field"], "customer.taxId")

    def test_safe_parsing_and_workspace_recovery(self):
        with self.assertRaises(InputError):
            parse_json('{"duplicate": 1, "duplicate": 2}')
        with self.assertRaises(InputError):
            parse_json("[" * 40 + "]" * 40)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "workspace.sqlite"
            connection = sqlite3.connect(path)
            connection.executescript("PRAGMA user_version=1; CREATE TABLE runs"
                                     "(id TEXT PRIMARY KEY, state TEXT NOT NULL, created TEXT NOT NULL, payload TEXT NOT NULL);"
                                     "INSERT INTO runs VALUES('older','finished','fixture','{}');")
            connection.close()
            store = Store(path)
            self.assertEqual(store.get("older")["state"], "finished")
            run = store.create()
            store.update(run, "running", {"records": [{"safe": True}]})
            self.assertEqual(Store(path).recover_interrupted(), 1)
            self.assertEqual(store.get(run)["records"], [{"safe": True}])
            token = Event()
            token.set()
            report = Workspace(root / "cancelled").analyze([FIXTURES / "support-exposed.json"], cancel=token)
            self.assertEqual(report["state"], "cancelled")

    def test_known_formats_and_inert_inputs(self):
        collection_schema = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        rows = [
            ("postman.json", {"info": {"schema": collection_schema}, "item": [{"item": [{
                "request": {"method": "GET", "url": "https://fixture.invalid/ok"},
                "response": [{"code": 200, "body": "{}"}], "event": [{"script": {"exec": ["fail()"]}}]}]}]},
             "Postman Collection v2.1", 2),
            ("variables.json", {"_postman_variable_scope": "environment", "values": [
                {"key": "sample", "value": "synthetic"}, {"key": "token", "value": "synthetic-key"}]}, "Postman variables", 0),
            ("newman.json", {"run": {"executions": [{"request": {"method": "GET", "url": "/ok"},
                                                    "response": {"code": 200, "body": "{}"}}]}}, "Newman JSON", 1),
            ("traffic.har", {"log": {"version": "1.2", "entries": [{"request": {"url": "/ok", "method": "GET"},
                "response": {"status": 200, "content": {"text": "e30=", "encoding": "base64"}}}]}}, "HAR 1.2", 1),
            ("insomnia.json", {"__export_format": 4, "resources": [{"_type": "request", "url": "/ok", "method": "GET"}]},
             "Insomnia JSON v4", 1),
            ("openapi.json", {"openapi": "3.1.0", "paths": {"/ok": {"get": {"responses": {"200": {
                "$ref": "https://fixture.invalid/remote.json"}}}}}}, "OpenAPI 3.1.0", 1),
        ]
        with tempfile.TemporaryDirectory() as folder, patch.object(socket.socket, "connect", side_effect=AssertionError):
            root = Path(folder)
            for filename, payload, name, count in rows:
                with self.subTest(filename=filename):
                    path = root / filename
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    imported = import_file(path, {"role": "support"})
                    self.assertEqual(imported.format, name)
                    self.assertEqual(len(imported.records), count)
                    for captured in imported.records:
                        self.assertTrue(captured.source_fingerprint)
                        self.assertEqual(captured.role, "support")
            yaml = root / "openapi.yaml"
            yaml.write_text("openapi: 3.0.3\npaths:\n  /ok:\n    get: {}\n", "utf-8")
            self.assertEqual(import_file(yaml).format, "OpenAPI 3.0.3")
            ndjson = root / "record.ndjson"
            ndjson.write_text('{"kind":"log","method":"GET","route":"/ok","body":"sample"}\n', "utf-8")
            self.assertEqual(import_file(ndjson).records[0].kind, "log")
            csv = root / "record.csv"
            csv.write_text("path,result,message\n/ok,200,sample\n", "utf-8")
            imported = import_file(csv, {"columns": {"route": "path", "status": "result", "body": "message"}})
            self.assertEqual(imported.records[0].status, 200)

    def test_two_definition_scopes_and_correlated_evidence(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(socket.socket, "connect", side_effect=AssertionError):
            root = Path(folder)
            paths = [root / name for name in ("first.json", "second.json")]
            for index, path in enumerate(paths):
                row = {"kind": "request", "api": f"fixture-{index}", "method": "GET", "route": f"/run/{index}"}
                path.write_text(json.dumps(row), encoding="utf-8")
            with self.assertRaises(InputError):
                prepare_definitions(paths, {"fixture-0": "https://a.example.test/run"})
            suite = prepare_definitions(paths, {"fixture-0": "https://a.example.test/run",
                                                "second.json": "https://b.example.test/run"})
            self.assertEqual([row["base"] for row in suite["operations"]],
                             ["https://a.example.test/run", "https://b.example.test/run"])
            response = record({"clean": True})
            response.request_id = "synthetic-1"
            response.source_id = "source-a"
            log = record("fixture log")
            log.kind = "log"
            log.request_id = response.request_id
            log.source_id = "source-b"
            linked = correlate([response.safe(), log.safe()])
            self.assertEqual(linked[0]["status"], "matched")
            self.assertEqual(linked[0]["sources"], ["source-a", "source-b"])

    def test_selected_openapi_reference_is_bound_to_response_status_and_type(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(socket.socket, "connect", side_effect=AssertionError):
            root = Path(folder)
            contract = root / "contract.json"
            definitions = root / "schemas.json"
            schema = {"type": "object", "properties": {"ready": {"type": "boolean"}}}
            definitions.write_text(json.dumps({"payload": schema}), encoding="utf-8")
            responses = {"200": {"content": {"application/json": {"schema": {"$ref": "schemas.json#/payload"}}}}}
            contract.write_text(json.dumps({"openapi": "3.1.0", "paths": {"/ready": {"get": {"responses": responses}}}}),
                                encoding="utf-8")
            self.assertIn("Remote, unselected or recursive reference skipped.", import_file(contract).warnings)
            mapping = {"local_references": (definitions,)}
            self.assertFalse(import_file(contract, mapping).warnings)
            suite = prepare_definitions([contract], {"default": "https://fixture.example.test/"}, mapping)
            self.assertEqual(suite["operations"][0]["response_schemas"], {"200 application/json": schema})
            with self.assertRaisesRegex(InputError, "distinct names"):
                import_file(contract, {"local_references": (definitions, definitions)})
