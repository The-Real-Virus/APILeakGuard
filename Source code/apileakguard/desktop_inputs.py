"""Import and functional request setup widgets."""
from pathlib import Path
from uuid import uuid4

from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout, QInputDialog, QLineEdit, QListWidget)

from .credentials import Credential, MemorySecrets
from .importers import read_document
from .model import InputError, parse_json
from .policies import load_policy
from .privacy import MASK, mask, mask_text
from .reports import atomic_write
from .requests import endpoint_text, operation_from_url, operation_scope, preview, private_http_target, scope_key
from .service import load_suite, prepare_definitions


class Inputs:
    def build_inputs(self):
        from .desktop import button, buttons, label, panel, text_area

        page = self.page("Automated tests", "Run automated tests",
                         "Run several requests together or repeat a saved plan. Start from URL makes a GET request for each endpoint you enter.")
        buttons(page, ("Open suite", self.open_suite), ("Start from URL", self.plan_url),
                ("From definitions", self.plan_definitions), ("Save suite", self.save_suite))
        buttons(page, ("Load saved suite", self.pick_saved_suite), ("Enter variables", self.set_variables),
                ("Choose run policy", self.set_run_policy))
        self.selected_run_policy = None
        self.include_evidence = QCheckBox("Analyze the selected evidence files in this run")
        page.addWidget(self.include_evidence)
        self.suite_preview = text_area("No plan selected. Open a suite, URL or request definitions.")
        self.pending_secrets = None
        page.addWidget(self.suite_preview, 1)
        buttons(page, ("Approve and run", self.run_suite, True), ("Rerun approved suite", lambda: self.run_suite(False)),
                ("Review discovered links", self.review_candidates))
        page = self.page("Imported evidence", "Analyze imported evidence",
                         "Choose local files or drop them onto the window. Analysis runs offline.")
        buttons(page, ("Choose files", self.open_imports), ("Choose folder", self.open_folder),
                ("Remove selection", lambda: self.set_paths([])))
        buttons(page, ("Preview files", self.inspect), ("Analyze files", self.analyze, True),
                ("Prepare functional suite", self.plan_definitions))
        self.schema_refs = []
        self.schemas_status = label("No local OpenAPI schema references selected.", "secondary", True)
        buttons(page, ("Choose local schema references", self.open_schema_refs),
                ("Clear references", self.clear_schema_refs))
        page.addWidget(self.schemas_status)
        mapping = panel(QFormLayout())
        self.import_fields = {}
        for key, title in (("api", "API"), ("environment", "Environment"), ("role", "Role"),
                           ("route", "Route"), ("columns", "CSV columns")):
            field = QLineEdit()
            self.import_fields[key] = field
            mapping.layout().addRow(title, field)
        self.import_fields["columns"].setPlaceholderText('{"route":"path","status":"code","body":"message"}')
        page.addWidget(mapping)
        self.file_list = QListWidget()
        self.file_list.setMaximumHeight(87)
        self.file_list.setAccessibleName("Selected evidence inputs")
        page.addWidget(self.file_list)
        self.import_preview = text_area("Preview formats, record counts and warnings before scanning.")
        page.addWidget(self.import_preview, 1)
        page = self.page("Manual request", "Send one API request",
                         "Paste the full endpoint URL from your API documentation. Preview it before anything is sent.")
        card = panel(QFormLayout())
        form = card.layout()
        self.method = QComboBox()
        self.method.addItems(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"])
        form.addRow("Method", self.method)
        endpoint = QLineEdit()
        endpoint.setPlaceholderText("https://api.example.com/orders/123")
        self.manual = {"path": endpoint}
        form.addRow("Endpoint URL", endpoint)
        self.manual_auth = QComboBox()
        self.manual_auth.addItems(["No authentication", "Bearer token", "Saved credential profile"])
        form.addRow("Authentication", self.manual_auth)
        self.manual_token = QLineEdit()
        self.manual_token.setEchoMode(QLineEdit.EchoMode.Password)
        self.manual_token.setPlaceholderText("Paste the token for this request plan")
        form.addRow("Token", self.manual_token)
        self.manual["profile"] = QLineEdit()
        self.manual["profile"].setPlaceholderText("Name saved in Settings")
        form.addRow("Saved profile", self.manual["profile"])
        self.manual_auth_note = label("", "secondary", True)
        form.addRow(self.manual_auth_note)
        self.manual_auth.currentTextChanged.connect(self.update_manual_auth)
        self.update_manual_auth()
        page.addWidget(card)
        buttons(page, ("Preview request", self.preview_manual, True))
        advanced = QCheckBox("Show advanced request settings")
        page.addWidget(advanced)
        card = panel(QFormLayout())
        form = card.layout()
        for key, title, value, hint in (
            ("base", "Base URL (optional)", "", "https://api.example.com/"),
            ("api", "API", "manual", ""),
            ("environment", "Environment", "test", ""),
            ("role", "Role", "", "Optional"),
            ("headers", "Headers JSON", "", '{"Accept":"application/json"}'),
            ("query", "Query parameters JSON", "", '{"limit":10}'),
            ("variables", "Variables JSON", "", '{"customerId":"1"}'),
        ):
            field = QLineEdit(value)
            field.setPlaceholderText(hint)
            self.manual[key] = field
            form.addRow(title, field)
        form.addRow(label("With a base URL, you can enter a relative endpoint like /orders/123 above.", "secondary", True))
        self.encoding = QComboBox()
        self.encoding.addItems(["text", "json", "form"])
        form.addRow("Body format", self.encoding)
        self.body = text_area("Optional JSON, form fields or text", editable=True)
        self.body.setFixedHeight(68)
        form.addRow("Body", self.body)
        page.addWidget(card)
        advanced.toggled.connect(card.setVisible)
        card.hide()
        page.addStretch()

        page = self.page("Projects and suites", "Projects and suites",
                         "Inspect saved scopes and select the projects and suites used for approved tests.")
        buttons(page, ("Import project scopes", self.load_project), ("Refresh workspace inventory", self.refresh_projects))
        self.projects_text = text_area("No named projects or suites are saved.")
        page.addWidget(self.projects_text, 1)
        self.refresh_projects()

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and all(url.isLocalFile() for url in event.mimeData().urls()):
            event.acceptProposedAction()

    def dropEvent(self, event):
        self.set_paths([Path(url.toLocalFile()) for url in event.mimeData().urls()])
        event.acceptProposedAction()

    def set_paths(self, paths):
        self.paths = list(paths)
        self.file_list.clear()
        self.file_list.addItems([mask_text(Path(path).name) for path in paths])
        self.import_preview.clear()
        self.select("Imported evidence")

    def open_imports(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose local evidence",
                                               filter="Evidence (*.json *.ndjson *.yaml *.yml *.har *.csv)")
        if paths:
            self.set_paths(paths)

    def open_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Choose evidence folder")
        if path:
            self.set_paths([path])

    def open_schema_refs(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose local OpenAPI reference files",
                                               filter="Schemas (*.json *.yaml *.yml)")
        if paths:
            if len(paths) > 16:
                self.error("Choose up to 16 local schema references.")
                return
            self.schema_refs = paths
            self.schemas_status.setText(f"{len(paths)} local OpenAPI schema references selected.")

    def clear_schema_refs(self):
        self.schema_refs = []
        self.schemas_status.setText("No local OpenAPI schema references selected.")

    def update_manual_auth(self, *_):
        mode = self.manual_auth.currentText()
        form = self.manual_token.parentWidget().layout()
        form.setRowVisible(self.manual_token, mode == "Bearer token")
        form.setRowVisible(self.manual["profile"], mode == "Saved credential profile")
        self.manual_auth_note.setText({
            "No authentication": "Choose this for public endpoints or an anonymous GET or HEAD on a private lab IP.",
            "Bearer token": "The token stays in memory for this request plan. Use HTTPS for a remote API.",
            "Saved credential profile": "Enter the profile name from Settings. Match its API and environment under advanced settings.",
        }[mode])
        if mode != "Bearer token":
            self.manual_token.clear()

    def mapping(self):
        values = {key: field.text().strip() for key, field in self.import_fields.items() if field.text().strip()}
        if "columns" in values:
            values["columns"] = parse_json(values["columns"])
        if self.schema_refs:
            values["local_references"] = tuple(self.schema_refs)
        return values

    def sample(self):
        self.set_paths([self.root / "fixtures/support-exposed.json"])
        self.analyze()

    def analyze(self):
        try:
            mapping = self.mapping()
        except InputError as error:
            self.error(str(error))
            return
        paths = self.paths[:]
        self.start("Analyzing selected evidence…",
                   lambda cancel, _progress: self.workspace.analyze(paths, mapping, cancel=cancel), self.show_report)

    def inspect(self):
        from .desktop import dump

        try:
            mapping = self.mapping()
        except InputError as error:
            self.error(str(error))
            return
        paths = self.paths[:]
        self.start("Inspecting selected files…", lambda _cancel, _progress: self.workspace.inspect_inputs(paths, mapping),
                   lambda value: self.import_preview.setPlainText(dump(value)))

    def set_suite(self, suite, secrets=None):
        try:
            plan = preview(suite)
            self.pending = suite
            self.pending_secrets = secrets
            self.suite_preview.setPlainText(self.describe_plan(plan))
            self.select("Automated tests")
        except (InputError, ValueError, TypeError, AttributeError) as error:
            self.error(str(error) if isinstance(error, InputError) else "The request plan contains invalid data.")

    def open_suite(self):
        value, _ = QFileDialog.getOpenFileName(self, "Choose a saved functional suite", filter="Suite (*.json *.yaml *.yml)")
        if value:
            try:
                self.set_suite(load_suite(value))
            except (OSError, InputError) as error:
                self.error(str(error) if isinstance(error, InputError) else "The suite could not be read.")

    def plan_url(self):
        source, ok = QInputDialog.getMultiLineText(self, "Start from URL", "Paste one full endpoint URL per line. "
                                                  "Example: https://api.example.com/orders")
        if ok:
            try:
                operations = [operation_from_url(line) for line in source.splitlines() if line.strip()]
                self.set_suite({"schema_version": 1, "operations": operations})
            except InputError as error:
                self.error(str(error))

    @staticmethod
    def describe_plan(plan):
        from .desktop import dump

        count = plan["request_count"]
        lines = [f"{count} request{'s' if count != 1 else ''} ready for review",
                 "Choose Approve and run to send this plan. Check the method, URL and authentication first.", ""]
        for row in plan["operations"]:
            profile = row["profile"] or "unauthenticated"
            auth = "None" if profile == "unauthenticated" else (
                "Bearer token (in memory)" if isinstance(profile, str) and profile.startswith("session-bearer-")
                else f"Saved profile {profile}")
            lines.extend((f"{row['method']}  {row['destination']}", f"Authentication: {auth}"))
            if row["private_lab_http"]:
                lines.append("Private lab HTTP. This plan sends no credentials.")
            if row["required_inputs"]:
                lines.append("Supply these values before running: " + ", ".join(row["required_inputs"]))
            if row["state_changing"]:
                lines.append("This method can change data on the server.")
            if row["headers"] or row["body"] is not None or row["query_parameters"]:
                lines.append("Request inputs (masked): " + dump({
                    "headers": row["headers"], "body": row["body"], "query fields": row["query_parameters"]}))
            lines.append("")
        return "\n".join(lines)

    def plan_definitions(self):
        if not self.paths:
            self.open_imports()
        if not self.paths:
            return
        origin, ok = QInputDialog.getMultiLineText(
            self, "Base URL for imported definitions",
            "Enter the server you can reach from this computer, such as https://api.example.com.\n"
            "You can also enter a JSON object mapping filenames or APIs to base URLs.")
        if not ok:
            return
        try:
            mapping = self.mapping()
            origin = origin.strip()
            scopes = parse_json(origin) if origin.startswith("{") else {"default": origin}
            if not isinstance(scopes, dict) or any(not isinstance(value, str) for value in scopes.values()):
                raise InputError("Enter a base URL or a JSON object of base URLs.")
            scopes = {name: endpoint_text(value) for name, value in scopes.items()}
        except InputError as error:
            self.error(str(error))
            return
        paths = self.paths[:]
        route = None
        if any(private_http_target(base) for base in scopes.values()):
            route, ok = QInputDialog.getText(self, "Choose a documented endpoint",
                                             "Enter one documented GET or HEAD path, such as /api/orders.")
            if not ok:
                return
            route = route.strip()

        self.start("Preparing functional request plan…",
                   lambda cancel, _progress: prepare_definitions(paths, scopes, mapping, cancel, only_route=route),
                   self.set_suite)

    def preview_manual(self):
        try:
            operation = {key: field.text().strip() for key, field in self.manual.items() if field.text().strip()}
            target = endpoint_text(operation.get("path", ""))
            if not target:
                raise InputError("Enter the endpoint URL you want to test, such as https://api.example.com/orders.")
            operation["path"] = target
            if "base" in operation:
                operation["base"] = endpoint_text(operation["base"])
            else:
                operation["base"] = operation_from_url(target)["base"]
            operation["method"] = self.method.currentText()
            if private_http_target(operation["base"]):
                operation["allow_private_http"] = True
            mode = self.manual_auth.currentText()
            if mode != "Saved credential profile":
                operation.pop("profile", None)
            elif not operation.get("profile"):
                raise InputError("Enter the saved credential profile name, or choose No authentication.")
            operation["approve_mutation"] = operation["method"] not in {"GET", "HEAD", "OPTIONS"}
            variables = parse_json(operation.pop("variables", "{}"))
            for key in ("headers", "query"):
                operation[key] = parse_json(operation.get(key, "{}"))
            body = self.body.toPlainText()
            if body:
                operation["encoding"] = self.encoding.currentText()
                operation["body"] = body if operation["encoding"] == "text" else parse_json(body)
            suite = {"schema_version": 1, "variables": variables, "operations": [operation]}
            registry = None
            if mode == "Bearer token":
                token = self.manual_token.text().strip()
                if token.lower().startswith("bearer "):
                    token = token[7:].strip()
                if not token or not token.isascii() or any(char.isspace() for char in token):
                    raise InputError("Paste a Bearer token for this endpoint, or choose No authentication.")
                operation["profile"] = "session-bearer-" + uuid4().hex
                registry = MemorySecrets()
                registry.put(("api", *scope_key(suite, operation)), Credential("bearer", token))
            self.set_suite(suite, registry)
        except InputError as error:
            self.error(str(error))

    def save_suite(self):
        from .desktop import dump

        if not self.pending:
            self.error("Preview a suite first.")
            return
        if self.pending_secrets is not None:
            self.error("To save this plan, choose a saved credential profile or No authentication in Manual request.")
            return
        name, accepted = QInputDialog.getText(self, "Save suite in the workspace", "Suite name")
        if accepted:
            try:
                self.workspace.save_suite(name, self.pending)
                self.refresh_projects()
            except InputError as error:
                self.error(str(error))
                return
        if mask(self.pending) != self.pending:
            self.error("The current suite contains sensitive-looking fields. Use credential references and synthetic inputs.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save functional suite", "suite.json", "JSON (*.json)")
        if path:
            try:
                atomic_write(path, dump(self.pending) + "\n", replace=Path(path).exists())
            except InputError as error:
                self.error(str(error))

    def refresh_projects(self):
        from .desktop import dump

        self.projects_text.setPlainText(dump({
            "projects": dict(self.workspace.store.settings("project:")),
            "suites": [{"name": name, "approved": self.workspace.approved(suite),
                        "requests": len(suite["operations"])}
                       for name, suite in self.workspace.store.settings("saved-suite:")],
        }))

    def load_project(self):
        from .desktop import dump

        path, _ = QFileDialog.getOpenFileName(self, "Choose project definition", filter="Project (*.json *.yaml *.yml)")
        if path:
            try:
                definition, _fingerprint = read_document(path)
                if self.confirm("Approve the selected project scopes", dump(mask(definition))):
                    self.workspace.save_project(definition)
                    self.refresh_projects()
            except (InputError, OSError) as error:
                self.error(str(error) if isinstance(error, InputError) else "The project definition could not be read.")

    def pick_saved_suite(self):
        suites = dict(self.workspace.store.settings("saved-suite:"))
        if not suites:
            self.error("There are no named saved suites. Preview and save a suite first.")
            return
        name, accepted = QInputDialog.getItem(self, "Load saved suite", "Suite", list(suites), editable=False)
        if accepted:
            self.set_suite(suites[name])

    def set_variables(self):
        from .desktop import dump

        if not self.pending:
            self.error("Select a request plan first.")
            return
        data, ok = QInputDialog.getMultiLineText(self, "Set plan variables", "JSON object of synthetic inputs",
                                                 dump(mask(self.pending.get("variables", {}))))
        if ok:
            try:
                self.set_suite({**self.pending, "variables": parse_json(data)}, self.pending_secrets)
            except InputError as error:
                self.error(str(error))

    def set_run_policy(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select policy for the next automated run",
                                             filter="Policy (*.json *.yaml *.yml)")
        try:
            self.selected_run_policy = load_policy(path) if path else None
            self.status.setText("Policy selected" if path else "Automated run policy cleared")
        except (InputError, OSError) as error:
            self.error(str(error) if isinstance(error, InputError) else "The policy could not be read.")

    def run_suite(self, prompt=True):
        if not self.pending:
            self.error("Preview a suite first.")
            return
        suite = self.pending
        registry = self.pending_secrets
        try:
            if prompt:
                plan = preview(suite)
                count = plan["request_count"]
                if not self.confirm(f"Send {count} approved {'request' if count == 1 else 'requests'}?",
                                    self.describe_plan(plan)):
                    return
                self.workspace.approve(suite, plan["suite_fingerprint"])
            paths = self.paths[:] if self.include_evidence.isChecked() else ()
            mapping = self.mapping() if paths else None
            policy = self.selected_run_policy
            self.start("Running approved requests…",
                       lambda cancel, progress: self.workspace.run(suite, paths=paths, mapping=mapping, policy=policy,
                                                                    cancel=cancel, progress=progress, secrets=registry),
                       self.show_report)
        except InputError as error:
            self.error(str(error))

    def include_selected_candidate(self):
        if self.display.currentText() != "Discovered links":
            self.error("Select a discovered link in the current run first.")
            return
        current = self.selected() or {}
        target = current.get("destination")
        if not target or MASK in target:
            self.error("The selected destination is missing or masked. Enter an authorized URL manually.")
            return
        if not self.pending:
            self.error("Open an approved base scope in a suite before selecting a candidate.")
            return
        if self.pending_secrets is not None:
            self.error("Preview a separate plan before adding a link. The in-memory Bearer token is for the current request.")
            return
        for operation in self.pending["operations"]:
            try:
                operation_scope(operation).check(target)
            except InputError:
                continue
            self.set_suite({**self.pending, "operations": [*self.pending["operations"],
                            {"api": operation.get("api", "api"), "environment": operation.get("environment", "test"),
                             "base": operation["base"], "method": "GET", "path": target,
                             "allow_private_http": operation.get("allow_private_http") is True}]})
            return
        self.error("The link is outside the selected suite's scope.")
