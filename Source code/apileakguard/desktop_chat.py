"""Desktop chat and confirmation of supported app actions."""
from pathlib import Path
from threading import Event

from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
                              QTextBrowser, QVBoxLayout, QWidget)

from .assistant_chat import MAX_MESSAGE, OPERATIONS, ask_chat, request_text
from .model import InputError
from .privacy import mask_text
from .providers import PROVIDERS


class Chat:
    def build_chat(self):
        from .desktop import button, buttons, label, panel

        footer = QWidget()
        footer_layout = QVBoxLayout(footer)
        footer_layout.setContentsMargins(1, 0, 5, 3)
        footer_layout.setSpacing(6)
        page = self.page("AI assistant", "AI assistant",
                         "Chat about API testing or ask the assistant to help with an app task.", footer=footer)
        self.chat_messages = []
        self.chat_approval = None
        self.chat_epoch = 0
        self.chat_proposal = None
        self.chat_cancel = None
        self.chat_followup = None

        controls = panel(QFormLayout())
        self.enabled = QCheckBox("Turn AI on for this session")
        self.enabled.toggled.connect(self.toggle_chat)
        controls.layout().addRow(self.enabled)
        self.provider = QComboBox()
        self.provider.addItems(list(PROVIDERS))
        self.provider_key = QLineEdit()
        self.provider_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.provider_key.setAccessibleName("Provider key")
        key_row = QHBoxLayout()
        key_row.addWidget(self.provider_key, 1)
        key_row.addWidget(button("Load key file…", self.load_chat_key))
        self.model = QComboBox()
        self.model.setEditable(True)
        self.model.setAccessibleName("Model")
        controls.layout().addRow("Provider", self.provider)
        controls.layout().addRow("Session key", key_row)
        controls.layout().addRow("Model", self.model)
        page.addWidget(controls)
        page.addWidget(label("Choose the provider for your key, then discover a chat model. "
                             "If you replace a key file, load it again for this session.", "secondary", True))
        self.provider.currentTextChanged.connect(self.change_chat_provider)
        self.provider_key.textChanged.connect(self.reset_chat)
        self.model.currentTextChanged.connect(self.invalidate_proposal)
        self.include_run = QCheckBox("Include the current run’s masked summary")
        self.include_run.toggled.connect(self.invalidate_proposal)
        page.addWidget(self.include_run)
        buttons(page, ("Discover chat models", self.discover_models), ("Review data shared", self.review_chat_data),
                ("New chat", self.reset_chat))
        self.chat_transcript = QTextBrowser()
        self.chat_transcript.setAccessibleName("Chat conversation")
        self.chat_transcript.setOpenLinks(False)
        self.chat_transcript.setOpenExternalLinks(False)
        self.chat_transcript.setPlaceholderText("Try “How do I test an API?” or “Open the sample evidence”.")
        page.addWidget(self.chat_transcript, 1)

        self.chat_proposal_label = QLabel()
        self.chat_proposal_label.setTextFormat(Qt.TextFormat.PlainText)
        self.chat_proposal_label.setWordWrap(True)
        footer_layout.addWidget(self.chat_proposal_label)
        row = QHBoxLayout()
        self.chat_action_button = button("Continue with action", self.execute_proposal, True)
        self.chat_dismiss = button("Dismiss action", self.dismiss_proposal)
        row.addWidget(self.chat_action_button)
        row.addWidget(self.chat_dismiss)
        row.addStretch()
        footer_layout.addLayout(row)
        self.chat_error = label("", "secondary", True)
        self.chat_error.setTextFormat(Qt.TextFormat.PlainText)
        footer_layout.addWidget(self.chat_error)
        self.chat_error.hide()
        composer = QHBoxLayout()
        self.question = QLineEdit()
        self.question.setMaxLength(MAX_MESSAGE)
        self.question.setAccessibleName("Chat message")
        self.question.setPlaceholderText("Type a message and press Enter")
        self.question.returnPressed.connect(self.send_chat)
        self.chat_send = button("Send", self.send_chat, True)
        composer.addWidget(self.question, 1)
        composer.addWidget(self.chat_send)
        footer_layout.addLayout(composer)
        self.show_proposal()
        self.toggle_chat(False)

    def toggle_chat(self, enabled):
        self.ai_indicator.setText("AI is on" if enabled else "AI is off")
        self.chat_send.setEnabled(enabled)
        self.question.setEnabled(enabled)
        self.chat_approval = None
        if not enabled:
            self.reset_chat()

    def change_chat_provider(self):
        self.reset_chat()
        self.provider_key.clear()
        self.model.clear()

    def invalidate_proposal(self, *_):
        self.chat_epoch += 1
        self.chat_approval = None
        self.chat_proposal = None
        self.show_proposal()
        self.chat_error.hide()

    def reset_chat(self, *_):
        self.invalidate_proposal()
        self.chat_messages.clear()
        self.chat_followup = None
        if hasattr(self, "chat_transcript"):
            self.chat_transcript.clear()
        if self.chat_cancel:
            self.chat_cancel.set()

    def chat_line(self, speaker, text):
        safe = mask_text(text, (self.provider_key.text(),))
        self.chat_messages.append((speaker, safe))
        del self.chat_messages[:-80]
        cursor = self.chat_transcript.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        if not self.chat_transcript.document().isEmpty():
            cursor.insertText("\n\n")
        cursor.insertText(speaker + "\n" + safe)
        self.chat_transcript.setTextCursor(cursor)
        self.chat_transcript.ensureCursorVisible()

    def chat_setup(self):
        if not self.enabled.isChecked():
            raise InputError("Turn AI on first.")
        key = self.provider_key.text().strip()
        if not key:
            raise InputError("Enter a session key for the selected provider.")
        return self.provider.currentText(), key, self.model.currentText().strip()

    def load_chat_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load provider key for this session", filter="Text files (*.txt)")
        if not path:
            return
        try:
            with Path(path).open(encoding="utf-8-sig") as stream:
                key = stream.read(8193).strip()
            # The adapter constructor validates the format without contacting the provider.
            PROVIDERS[self.provider.currentText()](key)
        except (OSError, UnicodeError, InputError):
            self.error("Could not load the key. Choose a UTF-8 text file containing one provider key.")
            return
        self.provider_key.setText(key)
        self.status.setText("Session key loaded. Discover chat models to check it with the selected provider.")

    def discover_models(self):
        try:
            provider, key, current = self.chat_setup()
        except InputError as error:
            self.error(str(error))
            return
        if self.task is not None:
            self.status.setText("Wait for the current job or cancel it first.")
            return
        epoch = self.chat_epoch
        self.chat_error.hide()

        def done(models):
            if epoch != self.chat_epoch:
                return
            self.model.clear()
            self.model.addItems(models)
            if current in models:
                self.model.setCurrentText(current)
            if models:
                self.chat_line("App", f"Found {len(models)} chat model candidates. "
                               f"Selected {self.model.currentText()}. Send Hi to test it.")
            else:
                self.chat_line("App", "No standard chat models were found for this key. "
                               "Enter a compatible model ID if your provider gave you one.")

        def failed(message):
            if epoch == self.chat_epoch:
                self.show_chat_error(f"{message} Select Discover chat models to try again.")

        self.start("Discovering chat models…", lambda _cancel, _progress: PROVIDERS[provider](key).chat_models(),
                   done, on_error=failed)

    def show_chat_error(self, message):
        self.chat_error.setText(mask_text(message, (self.provider_key.text(),)))
        self.chat_error.show()

    def chat_context(self):
        return self.report if self.include_run.isChecked() else None

    def review_chat_data(self):
        report = self.chat_context()
        details = request_text([*self.chat_messages, ("You", self.question.text())], report, self.provider_key.text())
        self.confirm("Preview the data in the next provider request", details)

    def resources(self):
        """Bind the proposal to the resources present when the message was sent."""
        return (self.report, self.pending, tuple(self.paths), tuple(self.schema_refs), self.patch, self.backup,
                self.selected())

    def send_chat(self):
        draft = self.question.text()
        message = draft.strip()
        if not message:
            return
        if self.task is not None:
            self.status.setText("Wait for the current job or cancel it first.")
            return
        try:
            provider, key, model = self.chat_setup()
            if not model:
                raise InputError("Discover chat models or enter a model ID first.")
            PROVIDERS[provider](key).model(model)
        except InputError as error:
            self.error(str(error))
            return
        report = self.chat_context()
        scope = (provider, model, report["run_id"] if report else None)
        if self.chat_approval != scope:
            preview = request_text([*self.chat_messages, ("You", message)], report, key)
            if not self.confirm(f"Send chat to {provider} using {mask_text(model, (key,))}", preview):
                return
            self.chat_approval = scope
        self.chat_proposal = None
        self.show_proposal()
        self.chat_error.hide()
        messages = [*self.chat_messages, ("You", message)]
        epoch, resources = self.chat_epoch, self.resources()
        self.chat_cancel = Event()

        def done(reply):
            self.chat_cancel = None
            if not self.enabled.isChecked() or epoch != self.chat_epoch:
                return
            if self.question.text() == draft:
                self.question.clear()
            self.chat_line("You", message)
            if reply.notice:
                self.chat_line("App", reply.notice)
            if reply.text:
                self.chat_line("Assistant", reply.text)
            if reply.action:
                self.chat_proposal = (reply.action, resources)
                self.show_proposal()

        def failed(message):
            self.chat_cancel = None
            if self.enabled.isChecked() and epoch == self.chat_epoch:
                note = " Your draft is still in the message box." if self.question.text() == draft else ""
                self.show_chat_error(message + note)

        self.start("Waiting for the assistant…",
                   lambda cancel, _progress: ask_chat(provider, model, key, messages, report, cancel),
                   done, on_error=failed, cancellation=self.chat_cancel)

    def show_proposal(self):
        if not hasattr(self, "chat_action_button"):
            return
        operation = OPERATIONS[self.chat_proposal[0]] if self.chat_proposal else None
        self.chat_proposal_label.setText(f"{operation.title} — {operation.effect}" if operation else "")
        for widget in (self.chat_proposal_label, self.chat_action_button, self.chat_dismiss):
            widget.setVisible(operation is not None)

    def dismiss_proposal(self):
        self.chat_proposal = None
        self.show_proposal()
        self.chat_line("App", "Action dismissed.")

    def execute_proposal(self):
        if not self.enabled.isChecked() or not self.chat_proposal or self.task is not None:
            return
        name, from_resources = self.chat_proposal
        self.chat_proposal = None
        self.show_proposal()
        operation = OPERATIONS[name]
        if from_resources != self.resources():
            self.chat_line("App", "The selected resources changed. Ask again to review the current selection.")
            return
        if operation.needs and not getattr(self, operation.needs, None):
            self.chat_line("App", f"Open {operation.page} and make the required selection, then ask again.")
            if operation.page:
                self.select(operation.page)
            return
        if operation.handler == "select":
            self.select(operation.page)
        else:
            if operation.page:
                self.select(operation.page)
            try:
                getattr(self, operation.handler)()
            except InputError as error:
                self.chat_line("App", str(error))
                self.select("AI assistant")
                return
            if self.task is not None:
                self.chat_followup = self.task
        if operation.handler != "assistant_coverage":
            self.chat_line("App", f"Continued with {operation.title.lower()}. Check the app for any selection or result.")

    def chat_job_finished(self, task, result=None, error=None):
        if not self.chat_followup or self.chat_followup is not task:
            return
        self.chat_followup = None
        if not self.enabled.isChecked():
            return
        if error:
            self.chat_line("App", error)
        elif isinstance(result, dict) and isinstance(result.get("summary"), dict):
            stats = result["summary"]
            self.chat_line("App", f"The local run is {result['state']} with {stats['coverage']} coverage "
                                 f"records and {stats['findings']} findings. Open Results and evidence to review it.")
        else:
            self.chat_line("App", "The local job finished. Its results are available in the app.")

    def assistant_coverage(self):
        stats = self.report.get("summary", {})
        self.display.setCurrentText("Coverage")
        self.chat_line("App", f"The selected run has {stats.get('coverage', 0)} coverage records, "
                             f"{stats.get('findings', 0)} findings, and {stats.get('candidates_pending', 0)} pending links.")
