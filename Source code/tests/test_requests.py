from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from threading import Event, Timer
import unittest

from apileakguard.credentials import Credential, MemorySecrets, WindowsSecrets
from apileakguard.model import InputError
from apileakguard.requests import preview
from apileakguard.service import Workspace
from fixture_api import fixture_pair, make_operation, make_suite


def approve_run(workspace, suite, **kwargs):
    workspace.approve(suite, preview(suite)["suite_fingerprint"])
    return workspace.run(suite, **kwargs)


class RequestTests(unittest.TestCase):
    def test_two_origins_discovery_and_exact_approval(self):
        with tempfile.TemporaryDirectory() as folder, fixture_pair() as (first, second):
            workspace = Workspace(folder)
            suite = make_suite(first, second)
            with self.assertRaises(InputError):
                workspace.run(suite)
            report = approve_run(workspace, suite)
            self.assertEqual(report["state"], "finished")
            self.assertEqual(report["summary"]["coverage"], 2)
            self.assertEqual(len(report["findings"]), 2)
            self.assertEqual(report["summary"]["candidates_pending"], 1)
            self.assertEqual([row[0] for row in first.calls], ["/v1/customer"])
            reopened = Workspace(folder)
            candidates = reopened.store.get(report["run_id"])["candidates"]
            self.assertEqual(candidates[0]["destination"], first.base + "/v1/next")
            suite["operations"].append(make_operation(first, candidates[0]["destination"]))
            with self.assertRaises(InputError):
                reopened.run(suite)
            approve_run(reopened, suite)
            self.assertIn("/v1/next", [row[0] for row in first.calls])

    def test_auth_cookie_isolation_redirect_and_scope(self):
        with tempfile.TemporaryDirectory() as folder, fixture_pair() as (first, second):
            secrets = MemorySecrets()
            workspace = Workspace(folder, secrets)
            for profile in ("support", "admin"):
                secrets.put(("api", "default", "Support fixture", "test", profile),
                            Credential("bearer", f"synthetic-{profile}"))
            suite = {"schema_version": 1, "operations": [
                make_operation(first, "/v1/session", role=role, profile=role)
                for role in ("support", "admin", "support", "admin")]}
            suite["operations"].append(make_operation(first, "/v1/jump", profile="support"))
            report = approve_run(workspace, suite)
            calls = first.calls[:4]
            self.assertEqual([call[2] for call in calls], ["", "", "sessionid=fixture-support", "sessionid=fixture-admin"])
            self.assertFalse(second.calls)
            self.assertNotIn("synthetic-support", json.dumps(report))
            self.assertNotIn("sessionid=fixture-support", json.dumps(report))
            out_of_scope = {"schema_version": 1, "operations": [
                make_operation(first, second.base + "/v1/next", profile="support")]}
            with self.assertRaises(InputError):
                preview(out_of_scope)
            self.assertFalse(second.calls)
            secrets.put(("api", "default", "Support fixture", "test", "expired"),
                        Credential("bearer", "expired-fixture"))
            expired = {"schema_version": 1, "operations": [make_operation(first, "/v1/session", profile="expired")]}
            invalid = approve_run(workspace, expired)
            self.assertEqual(invalid["state"], "incomplete")
            self.assertEqual(invalid["coverage"][0]["state"], "authentication failed")

    def test_cancel_partial_and_missing_inputs(self):
        with tempfile.TemporaryDirectory() as folder, fixture_pair() as (first, second):
            workspace = Workspace(folder)
            suite = make_suite(first, second)
            suite["operations"].insert(1, make_operation(first, "/v1/slow"))
            suite["operations"].insert(2, make_operation(first, "/v1/next"))
            token = Event()
            timer = Timer(0.35, token.set)
            timer.start()
            try:
                result = approve_run(workspace, suite, cancel=token)
            finally:
                timer.cancel()
            self.assertEqual(result["state"], "cancelled")
            self.assertTrue(result["records"])
            self.assertTrue(any(row["state"] == "skipped" for row in result["coverage"]))
            missing = {"schema_version": 1, "operations": [make_operation(first, "/v1/{{customer}}")]}
            skipped = approve_run(workspace, missing)
            self.assertEqual(skipped["state"], "incomplete")
            self.assertIn("Missing variable customer", skipped["coverage"][0]["reason"])

    def test_windows_secret_scope_local_delete_and_expiry(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            secrets = WindowsSecrets(path)
            scope = ("api", "p", "a", "test", "support")
            secrets.put(scope, Credential("key", "synthetic-private-test-secret", "X-Fixture-Key"))
            self.assertEqual(secrets.get(scope).name, "X-Fixture-Key")
            data = next(path.glob("*.dpapi")).read_text("ascii")
            self.assertNotIn("synthetic-private-test-secret", data)
            with self.assertRaises(InputError):
                secrets.get(("provider", "p", "a", "test", "support"))
            secrets.delete(scope)
            self.assertFalse(list(path.glob("*.dpapi")))
            expiry = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
            with self.assertRaisesRegex(InputError, "expired"):
                secrets.put(scope, Credential("bearer", "synthetic-expired", expires=expiry))
