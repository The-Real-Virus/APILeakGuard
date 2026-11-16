"""Project-local transactional run history and review tracking."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

from .model import InputError, canonical
from .privacy import mask
from .search import matches as search_matches, parse_query

DB_VERSION = 3


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def process_running(pid):
    if pid == os.getpid():
        return True
    if os.name != "nt":
        return Path(f"/proc/{pid}").exists()
    import ctypes as c
    from ctypes import wintypes as wt
    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel.OpenProcess.restype = wt.HANDLE
    kernel.GetExitCodeProcess.argtypes = [wt.HANDLE, c.POINTER(wt.DWORD)]
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return c.get_last_error() != 87
    try:
        exit_code = wt.DWORD()
        return not kernel.GetExitCodeProcess(handle, c.byref(exit_code)) or exit_code.value == 259
    finally:
        kernel.CloseHandle(handle)


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.open() as connection:
            connection.execute("BEGIN IMMEDIATE")
            version, = connection.execute("PRAGMA user_version").fetchone()
            if version > DB_VERSION:
                raise InputError("This workspace was created by a newer application version.")
            connection.execute("""CREATE TABLE IF NOT EXISTS runs
                (id TEXT PRIMARY KEY, state TEXT NOT NULL, created TEXT NOT NULL, payload TEXT NOT NULL)""")
            if "owner_pid" not in {row[1] for row in connection.execute("PRAGMA table_info(runs)")}:
                connection.execute("ALTER TABLE runs ADD COLUMN owner_pid INTEGER")
            connection.execute("""CREATE TABLE IF NOT EXISTS reviews
                (id TEXT PRIMARY KEY, payload TEXT NOT NULL)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS settings
                (id TEXT PRIMARY KEY, payload TEXT NOT NULL)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS evidence_index
                (run_id TEXT NOT NULL, ordinal INTEGER NOT NULL, record TEXT NOT NULL,
                folded TEXT NOT NULL, PRIMARY KEY(run_id, ordinal))""")
            connection.execute("PRAGMA user_version = 3")

    @contextmanager
    def open(self):
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def recover_interrupted(self):
        """Call only in an exclusively owned workspace profile."""
        with self.open() as connection:
            cursor = connection.execute("UPDATE runs SET state='incomplete' WHERE state IN ('queued','running')")
            return cursor.rowcount

    def recover_orphans(self):
        with self.open() as connection:
            candidates = connection.execute("SELECT id,owner_pid FROM runs WHERE state IN ('queued','running')").fetchall()
            orphans = [(run,) for run, pid in candidates if pid is None or not process_running(pid)]
            connection.executemany("UPDATE runs SET state='incomplete' WHERE id=? AND state IN ('queued','running')",
                                   orphans)
            return len(orphans)

    def create(self):
        identifier = uuid4().hex
        with self.open() as connection:
            connection.execute("INSERT INTO runs (id,state,created,payload,owner_pid) VALUES(?, 'queued', ?, '{}', ?)",
                               (identifier, timestamp(), os.getpid()))
        return identifier

    def update(self, identifier, state, safe_payload):
        if state not in {"queued", "running", "finished", "failed", "cancelled", "incomplete"}:
            raise InputError("Unknown job state.")
        with self.open() as connection:
            payload = json.dumps(safe_payload, ensure_ascii=True, allow_nan=False)
            cursor = connection.execute("UPDATE runs SET state=?, payload=? WHERE id=?", (state, payload, identifier))
            if cursor.rowcount != 1:
                raise InputError("Run ID could not be found.")
            count, = connection.execute("SELECT count(*) FROM evidence_index WHERE run_id=?", (identifier,)).fetchone()
            rows = [(ordinal + count, json.dumps(row, ensure_ascii=True)) for ordinal, row in
                    enumerate(safe_payload.get("records", [])[count:])]
            connection.executemany("INSERT INTO evidence_index VALUES(?,?,?,?)",
                                   [(identifier, ordinal, text, text.casefold()) for ordinal, text in rows])

    def get(self, identifier):
        with self.open() as connection:
            row = connection.execute("SELECT state, created, payload FROM runs WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise InputError("Run ID could not be found.")
        return {**json.loads(row[2]), "run_id": identifier, "state": row[0], "created": row[1]}

    def runs(self):
        with self.open() as connection:
            return [{"run_id": row[0], "state": row[1], "created": row[2]} for row in
                    connection.execute("SELECT id, state, created FROM runs ORDER BY created DESC, rowid DESC")]

    def search(self, identifier, term="", filters=None):
        term, query_filters = parse_query(term)
        with self.open() as connection:
            count, = connection.execute("SELECT count(*) FROM evidence_index WHERE run_id=?", (identifier,)).fetchone()
            matches = connection.execute(
                "SELECT record FROM evidence_index WHERE run_id=? AND instr(folded,?)>0 ORDER BY ordinal",
                (identifier, term.casefold())).fetchall()
        evidence = [json.loads(value) for value, in matches] if count else self.get(identifier).get("records", [])
        filters = {**query_filters, **(filters or {})}
        return [row for row in evidence if search_matches(row, term, filters)]

    def review(self, finding_id, status, note="", assignee=""):
        if status not in {"open", "reviewed", "false positive", "fixed", "pending verification"}:
            raise InputError("Unknown review status.")
        self.set_value("reviews", finding_id, mask({"status": status, "note": note, "assignee": assignee,
                                                  "updated": timestamp()}))

    def set_value(self, table, key, payload):
        if table not in {"reviews", "settings"}:
            raise InputError("Unknown workspace table.")
        with self.open() as connection:
            connection.execute(f"INSERT OR REPLACE INTO {table} VALUES (?, ?)", (key, canonical(payload)))

    def get_value(self, table, key, default=None):
        if table not in {"reviews", "settings"}:
            raise InputError("Unknown workspace table.")
        with self.open() as connection:
            row = connection.execute(f"SELECT payload FROM {table} WHERE id=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def settings(self, prefix):
        with self.open() as connection:
            rows = connection.execute("SELECT id, payload FROM settings WHERE substr(id,1,?)=? ORDER BY id",
                                      (len(prefix), prefix)).fetchall()
        return [(key[len(prefix):], json.loads(payload)) for key, payload in rows]
