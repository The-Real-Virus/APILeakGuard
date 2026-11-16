"""Console interface for APILeakGuard."""
import argparse
from getpass import getpass
import json
import os
from pathlib import Path
import sqlite3
import sys
import traceback

from . import VERSION
from .credentials import Credential, WindowsSecrets
from .fixes import apply_patch, preview_patch, restore_verified
from .importers import read_document
from .model import InputError, parse_json
from .policies import load_policy
from .privacy import mask_text
from .reports import atomic_write, compare_policies, compare_runs, export
from .requests import operation_from_url, preview
from .service import Workspace, load_suite, prepare_definitions, result_exit


def data_home():
    portable = Path(sys.executable).parent / "portable.profile"
    if getattr(sys, "frozen", False) and portable.is_file():
        return portable.parent / "profile"
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "APILeakGuard"


def output(value):
    print(json.dumps(value, ensure_ascii=True, indent=2, default=str))


def mapping_for(options):
    mapping = {key: getattr(options, key) for key in ("project", "api", "environment", "role", "route")
               if getattr(options, key, None)}
    if getattr(options, "columns", None):
        columns = parse_json(options.columns)
        if not isinstance(columns, dict) or any(not isinstance(value, str) for value in columns.values()):
            raise InputError("Use a JSON object mapping normalized field names to CSV columns.")
        mapping["columns"] = columns
    if getattr(options, "local_reference", None):
        mapping["local_references"] = tuple(options.local_reference)
    return mapping


def add_mapping(options):
    for key in ("project", "api", "environment", "role", "route", "columns"):
        options.add_argument("--" + key)
    options.add_argument("--local-reference", action="append", type=Path,
                         help="Allow a selected local OpenAPI reference file. Repeat for each approved file.")


def add_run_options(options):
    options.add_argument("--policy", type=Path)
    options.add_argument("--fail-on", default="high", choices=("critical", "high", "medium", "low", "info", "never"))


def parser():
    root = argparse.ArgumentParser(prog="apileakguard-cli", description="Functional API testing and offline leakage analysis.")
    root.add_argument("--version", action="version", version=f"APILeakGuard {VERSION}")
    root.add_argument("--workspace", type=Path, default=data_home(), help="Path to the local workspace profile.")
    root.add_argument("--diagnostics", action="store_true", help="Print exception types and code locations without input values.")
    commands = root.add_subparsers(dest="command", required=True)
    projects = commands.add_parser("project", help="List named projects or approve scopes from a project definition.")
    projects.add_argument("definition", nargs="?", type=Path)
    projects.add_argument("--approve-scope", action="store_true")
    saved = commands.add_parser("suites", help="List saved suites or save an exact selected suite by name.")
    saved.add_argument("--file", type=Path)
    saved.add_argument("--name")
    inspect = commands.add_parser("inspect", help="Preview imported file formats, counts and warnings.")
    inspect.add_argument("paths", type=Path, nargs="+")
    add_mapping(inspect)
    analyze = commands.add_parser("analyze", help="Analyze selected files offline.")
    analyze.add_argument("paths", type=Path, nargs="+")
    add_mapping(analyze)
    add_run_options(analyze)
    plan = commands.add_parser("plan", help="Prepare a reviewable suite from selected request definitions.")
    plan.add_argument("paths", type=Path, nargs="+")
    plan.add_argument("--scopes", required=True, help="JSON object of user-approved base URLs.")
    plan.add_argument("--only-route", help="Select an exact documented path (required for a private HTTP lab).")
    plan.add_argument("--out", type=Path)
    add_mapping(plan)
    for name in ("preview", "approve", "run"):
        command = commands.add_parser(name, help=f"{name.capitalize()} an exact functional suite.")
        command.add_argument("suite", type=Path)
        if name == "approve":
            command.add_argument("--fingerprint", required=True)
        if name == "run":
            command.add_argument("--evidence", type=Path, nargs="+")
            add_mapping(command)
            add_run_options(command)
    send = commands.add_parser("request", help="Preview or send one ordinary GET to an approved URL.")
    send.add_argument("url")
    send.add_argument("--fingerprint", help="Exact approval fingerprint shown by the preview.")
    send.add_argument("--api", default="manual")
    send.add_argument("--environment", default="test")
    send.add_argument("--project", default="default")
    commands.add_parser("runs", help="List local jobs.")
    for name in ("report", "inventory", "coverage", "remediation", "search", "policy-compare"):
        command = commands.add_parser(name, help=f"Inspect stored results with {name}.")
        command.add_argument("run_id")
        if name in {"report", "inventory", "coverage", "remediation", "policy-compare"}:
            command.add_argument("--out", type=Path)
            command.add_argument("--replace", action="store_true")
        if name == "search":
            command.add_argument("term")
            add_mapping(command)
        if name == "policy-compare":
            command.add_argument("policy", type=Path)
            command.add_argument("--against", type=Path, help="Compare with the result of this policy on the same run.")
    valid = commands.add_parser("policy-validate", help="Validate a versioned JSON or YAML policy.")
    valid.add_argument("policy", type=Path)
    difference = commands.add_parser("compare", help="Compare evidence from two stored runs.")
    difference.add_argument("before")
    difference.add_argument("after")
    review = commands.add_parser("review", help="Track an issue locally.")
    review.add_argument("finding")
    review.add_argument("status")
    review.add_argument("--note", default="")
    review.add_argument("--assignee", default="")
    fix = commands.add_parser("fix", help="Preview or apply a supported edit in a selected local directory.")
    fix.add_argument("root", type=Path)
    fix.add_argument("file", type=Path)
    fix.add_argument("field")
    fix.add_argument("--apply", metavar="PREVIEW_HASH", help="Confirm apply with the before hash shown by preview.")
    undo = commands.add_parser("rollback", help="Restore a verified original backed up by an approved local fix.")
    undo.add_argument("root", type=Path)
    undo.add_argument("file", type=Path)
    undo.add_argument("--before-hash", required=True)
    undo.add_argument("--applied-hash", required=True)
    undo.add_argument("--approve", action="store_true")
    secret = commands.add_parser("credential", help="Manage a project-local DPAPI credential.")
    secret.add_argument("operation", choices=("set", "delete"))
    secret.add_argument("project")
    secret.add_argument("api")
    secret.add_argument("environment")
    secret.add_argument("profile")
    secret.add_argument("--kind", choices=("bearer", "basic", "key", "cookie"), default="bearer")
    secret.add_argument("--name", default="")
    secret.add_argument("--expires")
    return root


def operate(options):
    command = options.command
    if command == "policy-validate":
        policy = load_policy(options.policy)
        output({"valid": True, "rules": len(policy["rules"]), "version": mask_text(policy["version"])})
        return 0
    secrets = WindowsSecrets(options.workspace / "credentials")
    workspace = Workspace(options.workspace, secrets)
    if command == "project":
        if options.definition:
            if not options.approve_scope:
                raise InputError("Review the named project definition and confirm with --approve-scope.")
            workspace.save_project(read_document(options.definition)[0])
        output(dict(workspace.store.settings("project:")))
        return 0
    if command == "suites":
        if options.file:
            if not options.name:
                raise InputError("Supply --name to save the selected suite.")
            workspace.save_suite(options.name, load_suite(options.file))
        output([{"name": name, "request_count": len(row["operations"]), "approved": workspace.approved(row)}
                for name, row in workspace.store.settings("saved-suite:")])
        return 0
    if command == "plan":
        suite = prepare_definitions(options.paths, parse_json(options.scopes), mapping_for(options),
                                    only_route=options.only_route)
        if options.out:
            atomic_write(options.out, json.dumps(suite, ensure_ascii=True, indent=2) + "\n")
        output(preview(suite))
        return 0
    if command == "credential":
        scope = ("api", options.project, options.api, options.environment, options.profile)
        if options.operation == "delete":
            secrets.delete(scope)
        else:
            if not sys.stdin.isatty():
                raise InputError("Enter the credential at an interactive console.")
            secrets.put(scope, Credential(options.kind, getpass("Secret: "), options.name, options.expires))
        output({"status": "saved" if options.operation == "set" else "deleted"})
        return 0
    if command in {"preview", "approve", "run", "request"}:
        if command == "request":
            operation = operation_from_url(options.url)
            suite = {"schema_version": 1, "project": options.project, "operations": [{
                **operation, "api": options.api, "environment": options.environment}]}
            if not options.fingerprint:
                output(preview(suite))
                return 0
            workspace.approve(suite, options.fingerprint)
        else:
            suite = load_suite(options.suite)
        if command == "preview":
            output(preview(suite))
            return 0
        if command == "approve":
            output({"approved": workspace.approve(suite, options.fingerprint)})
            return 0
        policy = load_policy(options.policy) if getattr(options, "policy", None) else None
        report = workspace.run(suite, policy=policy, paths=getattr(options, "evidence", None) or (),
                               mapping=mapping_for(options))
        output(report)
        return result_exit(report, getattr(options, "fail_on", "high"))
    if command == "inspect":
        output(workspace.inspect_inputs(options.paths, mapping_for(options)))
        return 0
    if command == "analyze":
        policy = load_policy(options.policy) if options.policy else None
        report = workspace.analyze(options.paths, mapping_for(options), policy)
        output(report)
        return result_exit(report, options.fail_on)
    if command in {"report", "inventory", "coverage", "remediation", "policy-compare"}:
        report = (workspace.policy_report(options.run_id, load_policy(options.policy)) if command == "policy-compare"
                  else workspace.store.get(options.run_id))
        if command == "policy-compare" and options.against:
            report["difference"] = compare_policies(
                workspace.policy_report(options.run_id, load_policy(options.against)), report)
        key = {"inventory": "candidates", "coverage": "coverage", "remediation": "remediation"}.get(command)
        value = {key: report.get(key, [])} if key else report
        if options.out:
            export(value, options.out, replace=options.replace)
        output(value)
        return 0
    if command == "search":
        output(workspace.store.search(options.run_id, options.term, mapping_for(options)))
    elif command == "compare":
        output(compare_runs(workspace.store.get(options.before), workspace.store.get(options.after)))
    elif command == "runs":
        output(workspace.store.runs())
    elif command == "review":
        workspace.store.review(options.finding, options.status, options.note, options.assignee)
        output({"status": options.status})
    elif command == "fix":
        patch = preview_patch(options.root, options.file, options.field)
        if options.apply:
            if options.apply != patch.before_hash:
                raise InputError("The source changed after preview. Preview again before applying.")
            apply_patch(patch, workspace.root / "backups")
        output({"field": mask_text(patch.field), "before_hash": patch.before_hash, "after_hash": patch.after_hash,
                "diff": patch.diff, "status": "applied" if options.apply else "preview"})
    elif command == "rollback":
        if not options.approve:
            raise InputError("Review the target and hashes, then confirm using --approve.")
        restore_verified(options.root, options.file, options.before_hash, options.applied_hash,
                         workspace.root / "backups")
        output({"status": "original restored"})
    return 0


def main():
    options = parser().parse_args()
    try:
        return operate(options)
    except InputError as error:
        print(mask_text(str(error)), file=sys.stderr)
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError) as error:
        if options.diagnostics:
            frames = traceback.extract_tb(error.__traceback__)
            locations = [f"{Path(frame.filename).name}:{frame.lineno} {frame.name}" for frame in frames]
            print(type(error).__name__ + " " + " > ".join(locations), file=sys.stderr)
        print("The selected input or local workspace could not be processed.", file=sys.stderr)
    except KeyboardInterrupt:
        print("Interrupted. Check the workspace for saved partial results.", file=sys.stderr)
        return 3
    return 4


if __name__ == "__main__":
    sys.exit(main())
