"""Remediation, theme settings and optional assistant widgets."""
from pathlib import Path

from PySide6.QtWidgets import (QComboBox, QFileDialog, QFormLayout, QInputDialog, QLineEdit)

from .credentials import Credential
from .fixes import apply_patch, preview_patch, rollback
from .model import InputError
from .privacy import mask_text
from .reports import compare_runs


class Tools:
    def build_tools(self):
        from .desktop import buttons, label, panel, text_area

        page = self.page("Remediation", "Plan and verify a fix",
                         "Review an exact masked diff, apply a supported local edit, and verify it with comparable evidence.")
        buttons(page, ("Preview local fix", self.choose_fix), ("Apply fix", self.apply_fix),
                ("Verify with new evidence", self.verify_fix, True), ("Rollback", self.backout))
        self.fix_details = text_area("Open a run to see its prioritized remediation plan.")
        page.addWidget(self.fix_details, 1)

        self.build_chat()

        page = self.page("Settings", "Workspace settings", "Set the theme and manage approved identities for your APIs.")
        card = panel(QFormLayout())
        self.theme = QComboBox()
        self.theme.addItems(["System", "Light", "Dark"])
        self.theme.setCurrentText(self.workspace.store.get_value("settings", "theme", "System"))
        self.theme.currentTextChanged.connect(self.save_theme)
        card.layout().addRow("Theme", self.theme)
        page.addWidget(card)
        card = panel()
        card.layout().addWidget(label("Authentication profiles", "panelTitle"))
        card.layout().addWidget(label("Store a credential for one project, API, environment and profile with Windows protection.", wrap=True))
        buttons(card.layout(), ("Save credential", self.save_credential),
                ("Remove credential", lambda: self.save_credential(True)))
        page.addWidget(card)
        page.addStretch()

    def save_theme(self, value):
        self.workspace.store.set_value("settings", "theme", value)
        self.set_theme()

    def choose_fix(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select a local JSON file to edit", filter="JSON (*.json)")
        if not path:
            return
        field, ok = QInputDialog.getText(self, "Preview local field removal", "Field path", text="body.customer.taxId")
        if ok:
            try:
                file = Path(path)
                self.patch = preview_patch(file.parent, file.name, field)
                self.backup = None
                self.fix_before = self.report
                self.fix_details.setPlainText(self.patch.diff + "\nValidation: parse JSON and scan comparable evidence.")
            except (InputError, OSError) as error:
                self.error(str(error) if isinstance(error, InputError) else "The source file is unavailable.")

    def apply_fix(self):
        if not self.patch:
            self.error("Preview a fix first.")
            return
        if self.confirm("Apply the previewed local edit", self.patch.diff):
            try:
                self.backup = apply_patch(self.patch, self.workspace.root / "backups")
                self.status.setText("Patch applied and JSON validated. Verify with new evidence.")
            except (InputError, OSError) as error:
                self.error(str(error) if isinstance(error, InputError) else "The source file is unavailable.")

    def verify_fix(self):
        from .desktop import dump

        if not self.patch or not self.backup or not self.fix_before:
            self.error("Select the original run and apply a previewed edit before verification.")
            return
        file = self.patch.root / self.patch.relative
        before = self.fix_before

        def done(report):
            self.show_report(report)
            result = compare_runs(before, report)
            self.workspace.store.set_value("settings", f"verification:{report['run_id']}", result)
            self.fix_details.setPlainText(dump(result))
            self.select("Remediation")

        self.start("Verifying the fix against local evidence…",
                   lambda cancel, _progress: self.workspace.analyze([file], cancel=cancel), done)

    def backout(self):
        if not self.patch or not self.backup:
            self.error("No applied edit is available to roll back.")
            return
        if self.confirm("Roll back the local edit", "Restore the original if the current file still matches the applied patch."):
            try:
                rollback(self.patch, self.backup)
                self.backup = None
                self.status.setText("Original restored")
            except (InputError, OSError) as error:
                self.error(str(error) if isinstance(error, InputError) else "The backup is unavailable.")

    def save_credential(self, remove=False):
        fields = []
        for label, default in (("Project", "default"), ("API", "manual"), ("Environment", "test"), ("Profile", "")):
            value, ok = QInputDialog.getText(self, "Authentication identity scope", label, text=default)
            if not ok or not value.strip():
                return
            fields.append(value.strip())
        scope = ("api", *fields)
        if remove:
            if self.confirm("Remove local credential", mask_text(" / ".join(fields))):
                self.workspace.secrets.delete(scope)
            return
        kind, ok = QInputDialog.getItem(self, "Select authentication type", "Type",
                                        ["bearer", "basic", "key", "cookie"], editable=False)
        if not ok:
            return
        header = ""
        if kind == "key":
            header, ok = QInputDialog.getText(self, "API key header", "Header name", text="X-API-Key")
            if not ok:
                return
        expires, ok = QInputDialog.getText(self, "Credential expiration", "ISO 8601 expiry with time zone (optional)")
        if not ok:
            return
        secret, ok = QInputDialog.getText(self, "Enter local credential", "Secret", QLineEdit.EchoMode.Password)
        if ok:
            try:
                self.workspace.secrets.put(scope, Credential(kind, secret, header, expires or None))
                self.status.setText("Credential saved with Windows protection")
            except (InputError, OSError) as error:
                self.error(str(error) if isinstance(error, InputError) else "Windows could not save the credential.")
