from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
import unittest

from apileakguard.assistant_chat import ask_chat
from apileakguard.model import InputError
from apileakguard.providers import Gemini, ProviderError
from apileakguard.requests import preview
from apileakguard.service import prepare_definitions

KEY = "fixture-provider-key-123456"
MESSAGES = [("You", f"Secret {KEY}"), ("Assistant", "Previous answer."), ("You", "Open the sample evidence.")]


class ChatContracts(unittest.TestCase):
    def test_gemini_discovery_prefers_a_general_chat_model(self):
        def transport(*_):
            return {"models": [{"name": "models/" + name, "supportedGenerationMethods": ["generateContent"]}
                               for name in ("antigravity-preview-05-2026", "gemini-3.5-flash",
                                            "gemini-2.5-flash", "gemini-2.5-flash-preview-tts")]}

        self.assertEqual(Gemini(KEY, transport=transport).chat_models(), ["gemini-3.5-flash", "gemini-2.5-flash"])

    def test_rejected_tool_format_can_continue_as_text(self):
        attempts = []

        def transport(_method, _url, _headers, payload):
            attempts.append("tools" in payload)
            if attempts[-1]:
                raise ProviderError(400)
            return {"candidates": [{"content": {"parts": [{"text": "Hi there."}]}}]}

        turn = ask_chat("Gemini", "model", KEY, [("You", "Hi")], None, Event(), transport=transport)
        self.assertEqual(attempts, [True, False])
        self.assertEqual(turn.text, "Hi there.")
        self.assertIsNone(turn.action)
        self.assertIn("text", turn.notice.lower())

    def test_all_providers_offer_optional_actions_with_history(self):
        for provider, response in (
            ("OpenAI", {"output": [{"type": "message", "content": [{"type": "output_text", "text": "Welcome."}]}]}),
            ("Claude", {"content": [{"type": "text", "text": "Welcome."}]}),
            ("Gemini", {"candidates": [{"content": {"parts": [{"text": "Welcome."}]}}]}),
        ):
            with self.subTest(provider=provider):
                def transport(method, _url, _headers, payload):
                    self.assertEqual(method, "POST")
                    self.assertIn("Previous answer.", str(payload))
                    self.assertIn("Open the sample evidence.", str(payload))
                    self.assertIn("review_coverage", str(payload["tools"]))
                    self.assertIn("open_sample", str(payload["tools"]))
                    self.assertNotIn(KEY, str(payload))
                    choice = (payload.get("tool_choice") or payload["toolConfig"]["functionCallingConfig"])
                    self.assertIn("auto", str(choice).lower())
                    return response

                self.assertEqual(ask_chat(provider, "model", KEY, MESSAGES, None, Event(), transport=transport).text,
                                 "Welcome.")

    def test_model_can_propose_only_known_argument_free_actions(self):
        def transport(name, args):
            return lambda *_: {"candidates": [{"content": {"parts": [
                {"functionCall": {"name": name, "args": args}}]}}]}

        proposal = ask_chat("Gemini", "model", KEY, MESSAGES, None, Event(),
                            transport=transport("open_sample", {}))
        self.assertEqual(proposal.action, "open_sample")
        for name, args in (("send_request", {}), ("open_sample", {"file": "unselected"})):
            with self.subTest(name=name), self.assertRaises(InputError):
                ask_chat("Gemini", "model", KEY, MESSAGES, None, Event(), transport=transport(name, args))
        cancel = Event()
        cancel.set()
        with self.assertRaisesRegex(InputError, "cancelled"):
            ask_chat("Gemini", "model", KEY, MESSAGES, None, cancel, transport=transport("open_sample", {}))

    def test_private_lab_transport_is_explicit_and_read_only(self):
        request = {"method": "GET", "base": "http://192.168.1.20:8888/api", "path": "/api/products"}
        with self.assertRaises(InputError):
            preview({"schema_version": 1, "operations": [request]})
        request["allow_private_http"] = True
        self.assertTrue(preview({"schema_version": 1, "operations": [request]})["operations"][0]["private_lab_http"])
        for mutation in ({"path": "/api/products?test=1"}, {"profile": "auth"}, {"method": "POST", "approve_mutation": True},
                         {"headers": {"X-Note": "example"}}, {"base": "http://example.com"},
                         {"path": "http://192.168.1.21:8888/api/products"}):
            with self.subTest(mutation=mutation), self.assertRaises(InputError):
                preview({"schema_version": 1, "operations": [{**request, **mutation}]})

    def test_definition_scope_override_uses_only_the_selected_lab_route(self):
        schema = """openapi: 3.0.0
info: {title: Test API, version: '1'}
servers: [{url: 'http://127.0.0.1:1234'}]
paths:
  /items:
    get: {responses: {'200': {description: OK}}}
  /other:
    get: {responses: {'200': {description: OK}}}
"""
        with TemporaryDirectory() as directory:
            path = Path(directory) / "test.yaml"
            path.write_text(schema, encoding="utf-8")
            scopes = {"default": "http://192.168.1.20:8888"}
            with self.assertRaisesRegex(InputError, "one documented"):
                prepare_definitions([path], scopes)
            result = preview(prepare_definitions([path], scopes, only_route="/items"))
            self.assertEqual(result["request_count"], 1)
            self.assertTrue(result["operations"][0]["private_lab_http"])
            self.assertEqual(result["operations"][0]["destination"], "http://192.168.1.20:8888/items")
            with self.assertRaisesRegex(InputError, "No matching"):
                prepare_definitions([path], scopes, only_route="/missing")
