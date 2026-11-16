import json
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

from apileakguard.assistant import Action, Assistant, COVERAGE_TOOL
from apileakguard.model import InputError
from apileakguard.providers import Claude, Gemini, OpenAI, ProviderError, Turn, https
from apileakguard.service import Workspace

KEY = "synthetic-provider-secret"
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "support-exposed.json"


class ContractTests(unittest.TestCase):
    def assert_contract(self, cls, headers, endpoints, explanation, action, payload_key):
        replies = iter((endpoints[0], explanation, action))
        calls = []

        def transport(method, url, actual_headers, payload):
            self.assertTrue(url.startswith(cls.base + "/"))
            self.assertEqual({key: actual_headers[key] for key in headers}, headers)
            if payload:
                self.assertNotIn(KEY, json.dumps(payload))
                self.assertNotIn("999-99-0000", json.dumps(payload))
            calls.append((method, url, payload))
            return next(replies)

        adapter = cls(KEY, transport)
        self.assertEqual(adapter.models(), ["model-test"])
        self.assertEqual(adapter.ask("model-test", f"key {KEY} tax value 999-99-0000").text, "Explanation.")
        self.assertEqual(adapter.ask("model-test", "Run coverage.", COVERAGE_TOOL), Turn("", "review_coverage", {}))
        self.assertEqual([row[0] for row in calls], ["GET", "POST", "POST"])
        self.assertEqual(calls[1][1], cls.base + endpoints[1])
        self.assertIn(payload_key, calls[2][2])
        self.assertIn("review_coverage", json.dumps(calls[2][2]))
        with self.assertRaises(InputError):
            adapter.ask("../wrong", "Test")

    def test_openai(self):
        self.assert_contract(
            OpenAI, {"Authorization": "Bearer " + KEY}, ({"data": [{"id": "model-test"}]}, "/responses"),
            {"output": [{"type": "message", "content": [{"type": "output_text", "text": "Explanation."}]}]},
            {"output": [{"type": "function_call", "name": "review_coverage", "arguments": "{}"}]}, "tool_choice")

    def test_claude(self):
        self.assert_contract(
            Claude, {"x-api-key": KEY, "anthropic-version": "2023-06-01"},
            ({"data": [{"id": "model-test"}], "has_more": False}, "/messages"),
            {"content": [{"type": "text", "text": "Explanation."}]},
            {"content": [{"type": "tool_use", "name": "review_coverage", "input": {}}]}, "tool_choice")

    def test_gemini(self):
        self.assert_contract(
            Gemini, {"x-goog-api-key": KEY},
            ({"models": [{"name": "models/model-test", "supportedGenerationMethods": ["generateContent"]},
                         {"name": "models/embedding-test", "supportedGenerationMethods": ["embedContent"]}]},
             "/models/model-test:generateContent"),
            {"candidates": [{"content": {"parts": [{"text": "Explanation."}]}}]},
            {"candidates": [{"content": {"parts": [{"functionCall": {"name": "review_coverage", "args": {}}}]}}]},
            "toolConfig")

    def test_provider_credential_error_is_sanitized(self):
        def denied(*_arguments):
            raise ProviderError(401)

        for adapter in (OpenAI, Claude, Gemini):
            with self.subTest(adapter=adapter.__name__):
                with self.assertRaisesRegex(ProviderError, "HTTP 401"):
                    adapter(KEY, denied).models()

    def test_network_failures_are_actionable_and_sanitized(self):
        for failure, expected in ((TimeoutError(KEY), "took too long"),
                                  (URLError(socket.gaierror(KEY)), "DNS"),
                                  (URLError(ssl.SSLError(KEY)), "secure connection"),
                                  (ConnectionResetError(KEY), "interrupted")):
            with self.subTest(failure=type(failure)), patch("apileakguard.providers.build_opener") as opener:
                http = opener.return_value
                http.open.side_effect = failure
                with self.assertRaisesRegex(ProviderError, expected) as raised:
                    https("POST", "https://provider.example.test/chat", {}, {})
                self.assertNotIn(KEY, str(raised.exception))
                http.open.assert_called_once()
                self.assertGreater(http.open.call_args.kwargs["timeout"], 15)

    def test_permission_boundary_and_default_off(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = Workspace(folder)
            run = workspace.analyze([FIXTURE])
            identifier = run["run_id"]
            valid = Turn("", "review_coverage", {})
            assistant = Assistant(workspace)
            with self.assertRaises(InputError):
                assistant.dispatch(valid, identifier, True)
            assistant.enabled = True
            for action in [Turn("", "run_suite", {}), Turn("", "review_coverage", {"run_id": "other"})]:
                with self.assertRaises(InputError):
                    assistant.dispatch(action, identifier, True)
            with self.assertRaises(InputError):
                assistant.dispatch(valid, identifier, False)
            self.assertEqual(assistant.dispatch(valid, identifier, True)["result"], run["summary"])

    def test_only_the_prebound_app_action_executes(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = Workspace(folder)
            assistant = Assistant(workspace, enabled=True)
            executed = []
            binding = Action("review_remediation", lambda cancel: executed.append(cancel.is_set()) or ["masked"])
            with self.assertRaises(InputError):
                assistant.dispatch(Turn(action="review_inventory", arguments={}), None, True, binding)
            with self.assertRaises(InputError):
                assistant.dispatch(Turn(action=binding.name, arguments={"path": "unselected"}), None, True, binding)
            self.assertFalse(executed)
            outcome = assistant.dispatch(Turn(action=binding.name, arguments={}), None, True, binding)
            self.assertEqual(outcome["result"], ["masked"])
            self.assertEqual(executed, [False])
