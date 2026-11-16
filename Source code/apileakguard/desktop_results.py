"""Evidence navigation, policy comparison, review and export widgets."""
from dataclasses import asdict
from http import HTTPStatus
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QDialog, QFileDialog, QHBoxLayout, QInputDialog, QLineEdit,
                               QListWidget, QSplitter, QVBoxLayout)

from .importers import import_file
from .model import InputError, parse_json
from .policies import load_policy, validate
from .policy_draft import chapters
from .reports import atomic_write, compare_policies, export
from .search import matches, parse_query


class Results:
    def build_results(self):
        from .desktop import button, buttons, label, text_area

        page = self.page("Results and evidence", "Results and evidence",
                         "Search masked evidence, inspect source records, and export the selected report.")
        self.summary = label("No run selected.", "panelTitle")
        page.addWidget(self.summary)
        self.http_outcome = label("", "secondary", True)
        self.http_outcome.hide()
        page.addWidget(self.http_outcome)
        row = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search masked evidence · role:support status:200")
        self.search.setAccessibleName("Search masked evidence")
        row.addWidget(self.search, 1)
        self.display = QComboBox()
        self.display.addItems(["Findings", "Evidence", "Requests", "Coverage", "Discovered links", "Remediation", "Run summary"])
        self.display.setAccessibleName("Result category")
        row.addWidget(self.display)
        self.view = QComboBox()
        self.view.addItems(["Pretty", "Raw"])
        self.view.setAccessibleName("Evidence view")
        row.addWidget(self.view)
        page.addLayout(row)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.items = QListWidget()
        self.items.setAccessibleName("Result items")
        self.details = text_area("Select a result to inspect it.")
        self.details.setAccessibleName("Selected evidence details")
        splitter.addWidget(self.items)
        splitter.addWidget(self.details)
        splitter.setSizes([270, 580])
        page.addWidget(splitter, 1)
        self.search.textChanged.connect(self.render_items)
        self.display.currentIndexChanged.connect(self.render_items)
        self.view.currentIndexChanged.connect(self.render_details)
        self.items.currentRowChanged.connect(self.render_details)
        buttons(page, ("Open source", self.open_source), ("Reveal original", self.reveal),
                ("Track finding", self.track), ("Export report", self.export_report, True))
        buttons(page, ("Add selected link to plan", self.include_selected_candidate),
                ("Export discovered links", self.export_candidates))

        page = self.page("Policy comparison", "Compare with policy",
                         "Evaluate a JSON or YAML field policy against the current saved run.")
        buttons(page, ("Choose policy", self.choose_policy), ("Compare with sample policy", self.sample_policy),
                ("Export comparison", lambda: self.export_value(self.policy_report)))
        buttons(page, ("Edit policy", self.edit_policy), ("Map policy source", self.map_policy),
                ("Compare relaxed example", lambda: self.compare_policy(self.root / "fixtures/support-policy-relaxed.json")))
        self.draft_policy = {"schema_version": 1, "version": "draft-1", "rules": []}
        self.policy_details = text_area("Open a run and choose a policy to see matched and unevaluated rules.")
        page.addWidget(self.policy_details, 1)

        page = self.page("Run history", "Run history",
                         "Open a finished, incomplete or cancelled job from this workspace.")
        self.history = QListWidget()
        self.history.itemDoubleClicked.connect(lambda _item: self.open_history())
        page.addWidget(self.history, 1)
        buttons(page, ("Open selected run", self.open_history, True), ("Refresh", self.refresh_history))

    def show_report(self, report):
        from .desktop import dump

        self.report = report
        summary = report.get("summary", {})
        counts = ((summary.get("findings", 0), "finding"), (summary.get("coverage", 0), "coverage record"),
                  (summary.get("candidates_pending", 0), "link"))
        findings, coverage, links = [f"{count} {noun}{'s' if count != 1 else ''}" for count, noun in counts]
        self.summary.setText(f"{report['state'].capitalize()}  ·  {findings}  ·  {coverage}  ·  {links} awaiting review")
        outcome = self.describe_http_outcome(report)
        self.http_outcome.setText(outcome)
        self.http_outcome.setVisible(bool(outcome))
        self.search.clear()
        self.display.setCurrentText("Findings" if report.get("findings") else "Evidence")
        self.render_items()
        self.fix_details.setPlainText(dump(report.get("remediation", [])))
        self.refresh_history()
        self.select("Results and evidence")

    @staticmethod
    def describe_http_outcome(report):
        responses = [row for row in report.get("records", []) if row.get("request") and row.get("status")]
        notes = []
        for row in responses[:3]:
            status = row["status"]
            try:
                phrase = HTTPStatus(status).phrase
            except ValueError:
                phrase = "Response"
            notes.append(f"HTTP {status} {phrase} — {row['method']} {row['route'] or '/'}")
            if status == 404:
                notes.append("The server replied. Check the path and method against the API docs or your Postman request.")
            elif status == 401:
                notes.append("The endpoint needs valid authentication. Choose Bearer token or a saved profile for an HTTPS endpoint.")
            elif status == 403:
                notes.append("The server refused access. Check the permissions or role for this endpoint.")
            elif row.get("media_type", "").lower().startswith("text/html"):
                notes.append("The server returned a web page. For API data, use the endpoint path from your API docs.")
            elif row.get("api") == "Practice API":
                notes.append("The request worked. Check Findings for the flagged email and Evidence for the masked response.")
        if len(responses) > 3:
            notes.append(f"{len(responses) - 3} more responses in Evidence.")
        failures = [row["reason"] for row in report.get("coverage", []) if row.get("reason")]
        if failures:
            notes.append("Request without a response: " + failures[0])
        return "\n".join(notes)
    def render_items(self, *_unused):
        from .desktop import dump

        self.items.clear()
        self.details.clear()
        self.rows = []
        if not self.report:
            return
        key = {"Findings": "findings", "Evidence": "records", "Requests": "requests", "Coverage": "coverage",
               "Discovered links": "candidates", "Remediation": "remediation", "Run summary": "summary"}[self.display.currentText()]
        values = self.report.get(key, [])
        if key == "requests":
            values = [row if row["kind"] == "request" else {
                **{key: row.get(key) for key in ("api", "environment", "project", "method", "route", "role",
                                               "source", "source_id", "location", "request_id")},
                **row["request"], "kind": "request",
            } for row in self.report.get("records", []) if row["kind"] == "request" or row.get("request")]
        if key == "summary":
            values = [{field: self.report.get(field) for field in ("summary", "warnings", "state", "run_id")}]
        term, filters = parse_query(self.search.text())
        self.rows = [row for row in values if matches(row, term, filters)]
        for row in self.rows:
            if key == "findings":
                caption = f"{row['severity'].upper()}  {row['field']}"
            elif key in {"records", "requests"}:
                caption = f"{row['kind'].capitalize()}  {row['method'] or ''}  {row['route'] or row['location']}"
            elif key == "candidates":
                caption = row["destination"]
            elif key == "coverage":
                caption = f"{row['state']}  {row['endpoint'][4] if len(row['endpoint']) > 4 else ''}"
            else:
                caption = row.get("field", "Run summary")
            self.items.addItem(caption)
        if self.rows:
            self.items.setCurrentRow(0)

    def selected(self):
        index = self.items.currentRow()
        return self.rows[index] if 0 <= index < len(self.rows) else None

    def render_details(self, *_unused):
        from .desktop import dump

        row = self.selected()
        if row is None:
            return
        pretty = self.view.currentText() == "Pretty"
        if pretty and "rationale" in row:
            review = self.workspace.store.get_value("reviews", row["id"], {})
            value = (
                f"{row['rule']}  /  {row['confidence']}\n\n{row['rationale']}\n\n"
                f"Field: {row['field']}\nEvidence: {row['evidence']}\n"
                f"Source: {row['source']} · {row['location']}\n\n"
                f"{row['remedy']}\n\n{row['verification']}\n\n"
                f"Finding ID: {row['id']}\nReview: {review.get('status', 'open')}\n"
                f"{review.get('note', '')}"
            )
        elif not pretty and row.get("raw_text") is not None:
            metadata = {key: value for key, value in row.items() if key not in {"raw_text", "body"}}
            value = dump(metadata) + "\n\nMasked source text\n\n" + row["raw_text"]
        else:
            value = dump(row, pretty)
        self.details.setPlainText(value)

    def focus_search(self):
        self.select("Results and evidence")
        self.search.setFocus()

    def open_source(self):
        row = self.selected() or {}
        if not row.get("source_id"):
            self.error("The selected result has no source record.")
            return
        self.display.setCurrentText("Evidence")
        self.search.setText(row["source_id"])

    def reveal(self):
        from .desktop import button, dump, text_area

        row = self.selected() or {}
        if not row.get("source_id"):
            self.error("Select an imported source record before revealing it.")
            return
        if row.get("source") == "approved suite":
            self.error("The live original is unavailable. This run retained masked evidence.")
            return
        file, _ = QFileDialog.getOpenFileName(self, "Choose the exact original evidence file")
        if not file:
            return
        try:
            records = import_file(file, self.mapping()).records
            original = next((item for item in records if item.source_id == row["source_id"]), None)
        except (InputError, OSError, TypeError):
            original = None
        if original is None:
            self.error("The original record is unavailable in the selected file.")
            return
        if self.confirm("Reveal the selected record locally", "Close the temporary view to restore masked display."):
            dialog = QDialog(self)
            dialog.setWindowTitle("Temporary local evidence")
            dialog.resize(650, 440)
            layout = QVBoxLayout(dialog)
            reveal = text_area()
            reveal.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
            reveal.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
            reveal.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            reveal.setPlainText(dump(asdict(original)))
            layout.addWidget(reveal)
            layout.addWidget(button("Close reveal", dialog.accept))
            dialog.exec()
            reveal.clear()
            dialog.deleteLater()

    def track(self):
        row = self.selected() or {}
        if "rationale" not in row:
            self.error("Select a finding to track.")
            return
        status, ok = QInputDialog.getItem(self, "Track finding", "Status",
                                        ["open", "reviewed", "false positive", "fixed", "pending verification"],
                                        editable=False)
        if ok:
            note, ok = QInputDialog.getText(self, "Track finding", "Local review note")
            if ok:
                self.workspace.store.review(row["id"], status, note)
                self.status.setText("Finding review saved")
                self.render_details()

    def review_candidates(self):
        if self.report is None:
            self.error("Open a run first.")
        else:
            self.select("Results and evidence")
            self.display.setCurrentText("Discovered links")

    def export_candidates(self):
        if self.report:
            self.export_value({"candidates": self.report.get("candidates", [])}, json_only=True)
        else:
            self.error("Open a run first.")

    def choose_policy(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose policy", filter="Policy (*.json *.yaml *.yml)")
        if path:
            self.compare_policy(path)

    def sample_policy(self):
        self.compare_policy(self.root / "fixtures/support-policy.json")

    def edit_policy(self):
        from .desktop import dump

        source, ok = QInputDialog.getMultiLineText(self, "Edit versioned field policy", "JSON policy",
                                                   dump(self.draft_policy))
        if not ok:
            return
        try:
            self.draft_policy = validate(parse_json(source))
        except InputError as error:
            self.error(str(error))
            return
        choice, ok = QInputDialog.getItem(self, "Validated policy", "Action",
                                          ["Compare with current run", "Save policy as JSON"], editable=False)
        if ok and choice == "Compare with current run":
            self.compare_policy(self.draft_policy)
        elif ok:
            path, _ = QFileDialog.getSaveFileName(self, "Save validated policy", "policy.json", "JSON (*.json)")
            if path and (not Path(path).exists() or self.confirm("Replace the selected policy", Path(path).name)):
                try:
                    atomic_write(path, dump(self.draft_policy) + "\n", replace=Path(path).exists())
                except InputError as error:
                    self.error(str(error))

    def map_policy(self):
        from .desktop import dump

        file, _ = QFileDialog.getOpenFileName(self, "Select business policy text",
                                              filter="Policy source (*.txt *.md *.docx)")
        if not file:
            return
        try:
            clauses = chapters(file)
        except (OSError, InputError) as error:
            self.error(str(error) if isinstance(error, InputError) else "The selected policy source could not be read.")
            return
        options = {f"{index + 1}. {clause[:100]}": index for index, clause in enumerate(clauses)}
        selected, ok = QInputDialog.getItem(self, "Map a policy clause", "Select a clause", list(options), editable=False)
        if not ok:
            return
        role, ok = QInputDialog.getText(self, "Map a policy clause", "Role (empty applies to all roles)")
        if not ok:
            return
        direction, ok = QInputDialog.getItem(self, "Map a policy clause", "Field behavior",
                                              ["Forbid", "Allow"], editable=False)
        if not ok:
            return
        path, ok = QInputDialog.getText(self, "Map a policy clause", "Dot-separated field pattern")
        if not ok or not path.strip():
            return
        mapped = options[selected]
        self.draft_policy = {"schema_version": 1, "version": "mapped-draft-1", "rules": [
            {"id": f"clause-{mapped + 1}", "scope": {"role": role} if role else {}, direction.lower(): [path]}],
            "unmapped_clauses": [clause for index, clause in enumerate(clauses) if index != mapped]}
        self.policy_details.setPlainText(dump(self.draft_policy))
        self.status.setText("Draft prepared. Review its rule and unmapped clauses in Edit policy.")

    def compare_policy(self, path):
        from .desktop import dump

        if self.report is None:
            self.error("Open a run before comparing a policy.")
            return
        identifier = self.report["run_id"]

        def done(report):
            previous = self.policy_report
            if previous and previous["run_id"] == report["run_id"]:
                report["difference"] = compare_policies(previous, report)
            self.policy_report = report
            self.policy_details.setPlainText(dump({key: report[key] for key in
                                                  ("policy_version", "difference", "policy_outcomes",
                                                   "findings", "remediation") if key in report}))

        self.start("Evaluating policy against saved evidence…",
                   lambda _cancel, _progress: self.workspace.policy_report(
                       identifier, path if isinstance(path, dict) else load_policy(path)), done)

    def export_value(self, report, json_only=False):
        if report is None:
            self.error("Select a report first.")
            return
        filters = "JSON (*.json)" if json_only else "JSON (*.json);;HTML (*.html);;CSV (*.csv)"
        path, kind = QFileDialog.getSaveFileName(self, "Save masked report", "report.json", filters)
        if not path:
            return
        suffix = {"HTML (*.html)": ".html", "CSV (*.csv)": ".csv"}.get(kind, ".json")
        destination = Path(path)
        if not destination.suffix:
            destination = destination.with_suffix(suffix)
        replace = destination.exists()
        if replace and not self.confirm("Replace the selected report", destination.name):
            return
        self.start("Exporting masked report…",
                   lambda _cancel, _progress: export(report, destination, replace=replace),
                   lambda _path: self.status.setText("Masked report exported"))

    def export_report(self):
        self.export_value(self.report)

    def refresh_history(self):
        self.history_rows = self.workspace.store.runs()
        self.history.clear()
        for row in self.history_rows:
            self.history.addItem(f"{row['created']}  ·  {row['state']}  ·  {row['run_id'][:12]}")

    def open_history(self):
        index = self.history.currentRow()
        if 0 <= index < len(self.history_rows):
            self.show_report(self.workspace.store.get(self.history_rows[index]["run_id"]))
