import os
from pathlib import Path
import tempfile
from time import monotonic
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog, QScrollArea

from apileakguard.assistant_chat import OPERATIONS
from apileakguard.desktop import Main
from apileakguard.providers import ProviderError, Turn
from apileakguard.service import Workspace
from fixture_api import fixture_pair


class DesktopChat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.window = Main(Workspace(Path(self.folder.name)))
        self.window.select("AI assistant")
        self.window.show()

    def tearDown(self):
        self.wait_for_job()
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()
        self.folder.cleanup()

    def wait_for_job(self):
        deadline = monotonic() + 5
        while self.window.task and monotonic() < deadline:
            QTest.qWait(15)
        self.assertIsNone(self.window.task)

    def test_chat_enter_history_consent_and_plain_text(self):
        w = self.window
        self.assertEqual(w.ai_indicator.text(), "AI is off")
        self.assertFalse(w.chat_send.isEnabled())
        w.enabled.click()
        self.assertEqual(w.ai_indicator.text(), "AI is on")
        w.provider_key.setText("synthetic-secret-example")
        w.model.setEditText("fixture-model")
        w.question.setText("Hello")
        with patch.object(w, "confirm", return_value=True) as consent, patch(
                "apileakguard.desktop_chat.ask_chat", side_effect=[Turn("Hello <developer>"), Turn("Your follow-up.")]) as ask:
            QTest.keyClick(w.question, Qt.Key.Key_Return)
            self.wait_for_job()
            w.question.setText("What did I say?")
            w.chat_send.click()
            self.wait_for_job()
            self.assertEqual(consent.call_count, 1)
            self.assertIn(("Assistant", "Hello <developer>"), ask.call_args.args[3])
        self.assertIn("Your follow-up.", w.chat_transcript.toPlainText())
        w.enabled.click()
        self.assertEqual(w.ai_indicator.text(), "AI is off")
        self.assertTrue(w.chat_transcript.document().isEmpty())

    def test_proposal_dismiss_changed_context_and_confirmed_job(self):
        w = self.window
        w.enabled.click()
        resources = w.resources()
        with patch.object(w, "sample", wraps=w.sample) as sample:
            w.chat_proposal = ("open_sample", resources)
            w.show_proposal()
            w.chat_dismiss.click()
            sample.assert_not_called()
            w.chat_proposal = ("open_sample", resources)
            w.paths = ["another-local-selection"]
            w.show_proposal()
            w.chat_action_button.click()
            sample.assert_not_called()
            w.chat_proposal = ("open_sample", w.resources())
            w.show_proposal()
            w.chat_action_button.click()
            self.wait_for_job()
            sample.assert_called_once()
        self.assertEqual(w.report["state"], "finished")
        self.assertIn("coverage records", w.chat_transcript.toPlainText())

    def test_all_assistant_operations_are_bound_to_real_controls(self):
        for name, action in OPERATIONS.items():
            with self.subTest(name=name):
                self.assertTrue(callable(getattr(self.window, action.handler)))
                if action.page:
                    self.assertIn(action.page, self.window.sections)

    def test_proposal_and_composer_stay_visible_at_minimum_window_size(self):
        w = self.window
        w.resize(w.minimumSize())
        w.enabled.click()
        w.chat_proposal = ("apply_fix", w.resources())
        w.show_proposal()
        self.app.processEvents()
        page = w.pages.currentWidget()
        scroll = page.findChild(QScrollArea)
        for value in (scroll.verticalScrollBar().minimum(), scroll.verticalScrollBar().maximum()):
            scroll.verticalScrollBar().setValue(value)
            for button in (w.chat_action_button, w.chat_dismiss, w.chat_send, w.question):
                self.assertTrue(button.isVisible())
                self.assertTrue(page.rect().contains(button.mapTo(page, QPoint(0, 0))))
                self.assertTrue(page.rect().contains(button.mapTo(page, button.rect().bottomRight())))

    def test_failed_message_remains_editable_and_retry_does_not_duplicate_history(self):
        w = self.window
        w.enabled.click()
        w.provider_key.setText("synthetic-provider-key")
        w.model.setEditText("fixture-model")
        w.question.setText("My draft")
        outcomes = [ProviderError(0, "The provider took too long to respond."), Turn("Hello.")]
        with patch.object(w, "confirm", return_value=True) as consent, patch(
                "apileakguard.desktop_chat.ask_chat", side_effect=outcomes) as ask:
            w.chat_send.click()
            self.wait_for_job()
            self.assertEqual(w.question.text(), "My draft")
            self.assertTrue(w.chat_error.isVisible())
            self.assertIn("too long", w.chat_error.text())
            self.assertEqual(w.chat_messages, [])
            w.chat_send.click()
            self.wait_for_job()
            self.assertEqual(ask.call_args.args[3], [("You", "My draft")])
            consent.assert_called_once()
        self.assertFalse(w.chat_error.isVisible())
        self.assertEqual(w.question.text(), "")
        self.assertEqual(w.chat_messages, [("You", "My draft"), ("Assistant", "Hello.")])

    def test_definitions_continues_from_first_file_selection(self):
        w = self.window
        path = Path(self.folder.name) / "definition.json"
        path.write_text('{"openapi":"3.0.0","paths":{"/items":{"get":{"responses":{}}}}}', encoding="utf-8")
        w.select("Automated tests")
        with patch.object(QFileDialog, "getOpenFileNames", return_value=([str(path)], "")), patch.object(
                QInputDialog, "getMultiLineText", return_value=("https://api.example.test", True)) as base:
            w.plan_definitions()
            self.wait_for_job()
            base.assert_called_once()
        self.assertEqual(w.nav.currentItem().text(), "Automated tests")
        self.assertIn("https://api.example.test/items", w.suite_preview.toPlainText())

    def test_manual_bearer_changes_the_http_outcome_without_persisting_the_token(self):
        w = self.window
        with fixture_pair() as (server, _), patch.object(w, "confirm", return_value=True):
            w.select("Manual request")
            w.manual["path"].setText(server.base + "/v1/session")
            w.preview_manual()
            w.run_suite()
            self.wait_for_job()
            self.assertIn(401, [row.get("status") for row in w.report["records"]])

            w.select("Manual request")
            w.manual_auth.setCurrentText("Bearer token")
            self.assertTrue(w.manual_token.isVisible())
            w.manual_token.setText("synthetic-support")
            w.preview_manual()
            self.assertNotIn("synthetic-support", repr(w.pending))
            self.assertIn("Bearer token (in memory)", w.suite_preview.toPlainText())
            w.run_suite()
            self.wait_for_job()
            self.assertEqual(server.calls, [("/v1/session", "", ""), ("/v1/session", "Bearer synthetic-support", "")])
            self.assertIn(200, [row.get("status") for row in w.report["records"]])
            self.assertNotIn("synthetic-support", repr(w.report))
