"""Native Windows workspace for APILeakGuard."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
from threading import Event

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (QApplication, QFrame, QHBoxLayout, QLabel, QListWidget, QMainWindow,
                               QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QStackedWidget,
                               QVBoxLayout, QWidget)

from . import VERSION
from .cli import data_home
from .credentials import WindowsSecrets
from .desktop_chat import Chat
from .desktop_inputs import Inputs
from .desktop_results import Results
from .desktop_tools import Tools
from .model import InputError
from .privacy import mask_text
from .practice import practice_request
from .service import Workspace

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
LINKS = {
    "GitHub": "https://github.com/The-Real-Virus",
    "LinkedIn": "https://www.linkedin.com/in/syed-muhammad-shah",
}


def dump(value, pretty=True):
    return json.dumps(value, ensure_ascii=False, indent=2 if pretty else None, default=str)


def label(value, name="", wrap=False):
    widget = QLabel(value)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setObjectName(name)
    widget.setWordWrap(wrap)
    return widget


def text_area(placeholder="", editable=False):
    widget = QPlainTextEdit()
    widget.setReadOnly(not editable)
    widget.setPlaceholderText(placeholder)
    return widget


def button(text, action, primary=False):
    widget = QPushButton(text)
    widget.clicked.connect(lambda _checked: action())
    if primary:
        widget.setObjectName("primary")
    return widget


def buttons(layout, *commands):
    row = QHBoxLayout()
    for command in commands:
        row.addWidget(button(*command))
    row.addStretch()
    layout.addLayout(row)


def panel(layout=None):
    box = QFrame()
    box.setObjectName("panel")
    box.setLayout(layout or QVBoxLayout())
    box.layout().setContentsMargins(16, 15, 16, 15)
    box.layout().setSpacing(10)
    return box


class Signals(QObject):
    done = Signal(object)
    error = Signal(str)
    progress = Signal(int)


class Task(QRunnable):
    def __init__(self, function):
        super().__init__()
        self.function = function
        self.cancel = Event()
        self.signals = Signals()

    def run(self):
        try:
            self.signals.done.emit(self.function(self.cancel, self.signals.progress.emit))
        except InputError as error:
            self.signals.error.emit(mask_text(str(error)))
        except Exception:
            self.signals.error.emit("The operation could not be completed. Check the selected input and saved job state.")


class Verification(QObject):
    """Local instrumentation for the two profile destinations and isolated system theme checks."""
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.theme_shortcut = QShortcut(QKeySequence("Ctrl+Shift+F9"), window)
        self.theme_shortcut.activated.connect(self.flip_theme)
        QDesktopServices.setUrlHandler("https", self, "link")

    @Slot(QUrl)
    def link(self, url):
        target = url.toString()
        name = next((name for name, value in LINKS.items() if value == target), None)
        if name is not None:
            self.window.workspace.store.set_value("settings", "verification:link:" + name, target)
            self.window.status.setText(f"Verified {name} destination")

    def flip_theme(self):
        hints = QApplication.instance().styleHints()
        target = Qt.ColorScheme.Light if hints.colorScheme() == Qt.ColorScheme.Dark else Qt.ColorScheme.Dark
        hints.setColorScheme(target)
        self.window.workspace.store.set_value("settings", "verification:system-appearance", target.name)


class Main(QMainWindow, Inputs, Results, Tools, Chat):
    def __init__(self, workspace):
        super().__init__()
        self.workspace = workspace
        self.root = ROOT
        self.task = self.report = self.pending = self.policy_report = None
        self.patch = self.backup = self.fix_before = None
        self.paths = []
        self.rows = []
        self.sections = {}
        self.setWindowTitle(f"APILeakGuard {VERSION}")
        self.setWindowIcon(QIcon(str(ROOT / "assets/apileakguard.ico")))
        self.setMinimumSize(805, 540)
        self.resize(1130, 725)
        self.setAcceptDrops(True)
        shell = QWidget()
        layout = QHBoxLayout(shell)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        sidebar = QWidget()
        sidebar.setFixedWidth(210)
        sidebar.setObjectName("sidebar")
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(14, 19, 14, 16)
        side.setSpacing(11)
        brand = QHBoxLayout()
        image = QLabel()
        image.setPixmap(self.windowIcon().pixmap(34, 34))
        brand.addWidget(image)
        brand.addWidget(label("APILeakGuard", "brand"), 1)
        side.addLayout(brand)
        side.addWidget(label("WORKSPACE", "section"))
        self.nav = QListWidget()
        self.nav.setAccessibleName("Workspace navigation")
        self.nav.setObjectName("nav")
        side.addWidget(self.nav, 1)
        self.ai_indicator = label("AI is off", "secondary")
        side.addWidget(self.ai_indicator)
        side.addWidget(label("Made By ViRuS", "credit"))
        side.addWidget(label("© 2026. All rights reserved.", "secondary"))
        profiles = QHBoxLayout()
        for name, url in LINKS.items():
            control = button("", lambda url=url: QDesktopServices.openUrl(QUrl(url)))
            control.setIcon(QIcon(str(ROOT / "assets" / f"{name.lower()}.svg")))
            control.setAccessibleName(name)
            control.setToolTip(name)
            control.setFixedWidth(34)
            profiles.addWidget(control)
        profiles.addStretch()
        profiles.addWidget(label(VERSION, "section"))
        side.addLayout(profiles)
        layout.addWidget(sidebar)
        body = QWidget()
        column = QVBoxLayout(body)
        column.setContentsMargins(21, 14, 21, 14)
        strip = QHBoxLayout()
        self.status = label("Ready", "secondary")
        strip.addWidget(self.status, 1)
        self.cancel_button = button("Cancel job", self.cancel_task)
        self.cancel_button.setEnabled(False)
        strip.addWidget(self.cancel_button)
        column.addLayout(strip)
        self.pages = QStackedWidget()
        column.addWidget(self.pages, 1)
        layout.addWidget(body, 1)
        self.nav.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.setCentralWidget(shell)
        self.home_page()
        self.build_inputs()
        self.build_results()
        self.build_tools()
        self.select("Overview")
        self.set_theme()
        QApplication.instance().styleHints().colorSchemeChanged.connect(self.set_theme)
        self.open_shortcut = QShortcut(QKeySequence("Ctrl+O"), self)
        self.open_shortcut.activated.connect(self.open_imports)
        self.find_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        self.find_shortcut.activated.connect(self.focus_search)
        self.refresh_history()

    def page(self, nav, title, description, *, footer=None):
        self.sections[nav] = self.nav.count()
        self.nav.addItem(nav)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        widget = QWidget()
        column = QVBoxLayout(widget)
        column.setContentsMargins(1, 4, 5, 3)
        column.setSpacing(13)
        column.addWidget(label(title, "title"))
        column.addWidget(label(description, "secondary", True))
        scroll.setWidget(widget)
        if footer is None:
            self.pages.addWidget(scroll)
        else:
            frame = QWidget()
            layout = QVBoxLayout(frame)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(6)
            layout.addWidget(scroll, 1)
            layout.addWidget(footer)
            self.pages.addWidget(frame)
        return column

    def select(self, section):
        self.nav.setCurrentRow(self.sections[section])

    def home_page(self):
        page = self.page("Overview", "Test an API response",
                         "Send a request, check the server’s status and response, and see which fields may expose sensitive data.")
        sample = panel()
        sample.layout().addWidget(label("Try one request on this computer", "panelTitle"))
        sample.layout().addWidget(label("Run a local GET for a sample customer. The server returns HTTP 200. "
                                        "The app flags the example email. Open Evidence to see the masked response.", wrap=True))
        buttons(sample.layout(), ("Run practice request", self.run_practice, True),
                ("Open sample evidence", self.sample))
        page.addWidget(sample)
        cards = QHBoxLayout()
        for title, description, section in (
            ("Send one request", "Paste an endpoint URL and choose authentication. See exactly what the server returns.", "Manual request"),
            ("Run several requests", "Start from a list of endpoint URLs or rerun a saved set of requests.", "Automated tests"),
            ("Review saved responses", "Import Postman results, captures or logs for offline analysis.", "Imported evidence"),
        ):
            card = panel()
            card.layout().addWidget(label(title, "panelTitle"))
            card.layout().addWidget(label(description, wrap=True))
            buttons(card.layout(), ("Open workflow", lambda key=section: self.select(key)))
            cards.addWidget(card, 1)
        page.addLayout(cards)
        page.addStretch()

    def run_practice(self):
        self.start("Running the local practice request…",
                   lambda cancel, progress: practice_request(self.workspace, cancel, progress), self.show_report)

    def confirm(self, title, detail):
        dialog = QMessageBox(self)
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setWindowTitle("APILeakGuard")
        dialog.setIcon(QMessageBox.Icon.Question)
        dialog.setText(title)
        if len(detail) > 360:
            dialog.setInformativeText("Expand the details to review before allowing the action.")
            dialog.setDetailedText(detail)
        else:
            dialog.setInformativeText(detail)
        allow = dialog.addButton("Allow", QMessageBox.ButtonRole.AcceptRole)
        cancel = dialog.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        dialog.setDefaultButton(cancel)
        dialog.exec()
        return dialog.clickedButton() is allow

    def error(self, message):
        message = mask_text(message)
        self.status.setText(message)
        dialog = QMessageBox(self)
        dialog.setWindowTitle("APILeakGuard")
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(message)
        dialog.setIcon(QMessageBox.Icon.Warning)
        dialog.exec()

    def start(self, message, function, callback, *, on_error=None, cancellation=None):
        if self.task is not None:
            self.status.setText("Wait for the current job or cancel it first.")
            return
        self.status.setText(message)
        self.task = Task(function)
        if cancellation is not None:
            self.task.cancel = cancellation
        self.callback = callback
        self.on_error = on_error
        self.task.signals.done.connect(self.done)
        self.task.signals.error.connect(self.failed)
        self.task.signals.progress.connect(lambda n: self.status.setText(f"Processed {n} requests"))
        self.cancel_button.setEnabled(True)
        QThreadPool.globalInstance().start(self.task)

    def done(self, result):
        task = self.task
        self.task = None
        self.cancel_button.setEnabled(False)
        self.status.setText("Ready")
        self.callback(result)
        self.chat_job_finished(task, result=result)

    def failed(self, message):
        task = self.task
        self.task = None
        self.cancel_button.setEnabled(False)
        if self.on_error:
            self.status.setText("Ready")
            self.on_error(message)
        else:
            self.error(message)
        self.chat_job_finished(task, error=message)

    def cancel_task(self):
        if self.task:
            self.task.cancel.set()
            self.status.setText("Cancelling at the next safe boundary…")

    def closeEvent(self, event):
        if self.task:
            self.cancel_task()
            event.ignore()
        else:
            super().closeEvent(event)

    def dragEnterEvent(self, event):
        Inputs.dragEnterEvent(self, event)

    def dropEvent(self, event):
        Inputs.dropEvent(self, event)

    def set_theme(self, *_):
        mode = self.theme.currentText()
        dark = mode == "Dark" or (mode == "System" and
            QApplication.instance().styleHints().colorScheme() == Qt.ColorScheme.Dark)
        bg, surface, sidebar, fg, secondary, border, accent, selected, fill = (
            ("#111a23", "#192630", "#101923", "#eef5f4", "#b9ccce", "#334650", "#81ddd0", "#274b50", "#102924")
            if dark else
            ("#f4f7f8", "#ffffff", "#e8f0f2", "#142735", "#405965", "#c6d5da", "#00695e", "#d4ebe8", "#ffffff")
        )
        self.setStyleSheet(f"""
        QMainWindow,QDialog,QMessageBox,QScrollArea,QScrollArea > QWidget > QWidget {{background:{bg};}}
        QWidget {{color:{fg};font:10.5pt 'Segoe UI';}}
        QWidget#sidebar {{background:{sidebar};border-right:1px solid {border};}}
        QLabel#brand {{font-size:14pt;font-weight:700;}}
        QLabel#title {{font-size:24pt;font-weight:700;}}
        QLabel#panelTitle {{font-size:13pt;font-weight:700;}}
        QLabel#secondary,QLabel#section {{color:{secondary};}}
        QLabel#section {{font-size:9pt;font-weight:700;padding:4px;}}
        QFrame#panel {{background:{surface};border:1px solid {border};border-radius:9px;}}
        QListWidget,QPlainTextEdit,QTextBrowser,QLineEdit,QComboBox {{
          background:{surface};border:1px solid {border};border-radius:5px;padding:6px;
          selection-background-color:{selected};selection-color:{fg};}}
        QPlainTextEdit {{font:10pt 'Consolas';}}
        QListWidget::item {{padding:7px;}}
        QListWidget::item:selected {{background:{selected};color:{fg};}}
        QListWidget#nav {{background:{sidebar};border:0;padding:0;}}
        QListWidget#nav::item {{border-radius:5px;padding:8px;}}
        QListWidget#nav::item:selected {{color:{accent};font-weight:700;}}
        QPushButton {{background:{surface};border:1px solid {border};border-radius:5px;padding:6px 9px;}}
        QPushButton:hover {{background:{selected};}}
        QPushButton#primary:disabled {{background:{surface};color:{secondary};border-color:{border};}}
        QPushButton:focus,QLineEdit:focus,QComboBox:focus,QListWidget:focus {{border:2px solid {accent};}}
        QPushButton:disabled {{color:{secondary};}}
        QPushButton#primary {{background:{accent};color:{fill};font-weight:700;}}
        """)


def main():
    parser = argparse.ArgumentParser(prog="APILeakGuard")
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--verification-mode", action="store_true",
                        help="Record profile destinations locally and simulate app-only system appearance changes.")
    args = parser.parse_args()
    if args.verification_mode and args.workspace is None:
        parser.error("--verification-mode requires a selected test workspace")
    root = args.workspace or data_home()
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("ViRuS.APILeakGuard.1")
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontUseNativeDialogs, True)
    app = QApplication([sys.argv[0]])
    app.setApplicationName("APILeakGuard")
    app.setStyle("Fusion")
    app.setWindowIcon(QIcon(str(ROOT / "assets/apileakguard.ico")))
    try:
        window = Main(Workspace(root, WindowsSecrets(root / "credentials")))
    except (InputError, OSError, sqlite3.Error):
        QMessageBox.critical(None, "APILeakGuard", "The selected workspace could not be opened.")
        return 4
    if args.verification_mode:
        window.verification = Verification(window)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
