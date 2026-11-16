"""Assemble the standalone Windows ZIP and release hashes."""
import argparse
from hashlib import file_digest, sha256
import importlib.metadata as metadata
import json
from pathlib import Path
import shutil
import sys
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / ".work" / "build"
RELEASE = ROOT / "release"
DIST = ROOT / "dist"
VERSION = "v1.0"
RELEASE_NAME = "APILeakGuard-v1.0-windows-x64"
PORTABLE = RELEASE / f"{RELEASE_NAME}-portable.zip"
SOURCE = WORK / "APILeakGuard-v1.0-source.zip"


def hash_file(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def zip_tree(path, sources, relative):
    with ZipFile(path, "w", compression=ZIP_DEFLATED, compresslevel=6) as archive:
        for source in sorted(sources):
            info = ZipInfo(relative(source), (2026, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            with source.open("rb") as stream, archive.open(info, "w") as destination:
                shutil.copyfileobj(stream, destination)


def paths_under(root):
    return [item for item in root.rglob("*") if item.is_file()]


def collect_licenses(output):
    output.mkdir(parents=True, exist_ok=True)
    runtime = Path(sys.base_prefix)
    for name in ("LICENSE.txt", "LICENSE", "LICENSE.rtf"):
        if (runtime / name).is_file():
            shutil.copy2(runtime / name, output / "Python-license.txt")
            break
    for dependency in metadata.distributions():
        name = dependency.metadata["Name"]
        if name.lower() in {"pip", "wheel"}:
            continue
        license_paths = [path for path in (dependency.files or ())
                         if any(part.lower().startswith(("license", "copying", "notice")) for part in path.parts)]
        for entry in license_paths:
            source = dependency.locate_file(entry)
            if source.is_file():
                destination = output / name / "__".join(entry.parts[-3:])
                destination.parent.mkdir(exist_ok=True)
                shutil.copy2(source, destination)


def prepare():
    runtime = DIST / "APILeakGuard-v1.0"
    shutil.copytree(DIST / "gui", runtime, dirs_exist_ok=True)
    shutil.copytree(DIST / "cli", runtime, dirs_exist_ok=True)
    for name in ("README.md", "RELEASE-NOTES.md", "LICENSE", "THIRD-PARTY-NOTICES.md",
                 "docs/HANDBOOK.md", "docs/REMAINING-TESTS.md", "docs/OPERATIONS.md", "docs/DESKTOP-CONTROLS.md"):
        path = ROOT / name
        if path.is_file():
            destination = runtime / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
    collect_licenses(runtime / "licenses")
    shutil.copytree(ROOT / "fixtures", runtime / "fixtures")
    for name in ("APILeakGuard.exe", "apileakguard-cli.exe"):
        if not (runtime / name).is_file():
            raise RuntimeError("A packaged executable is missing.")
    marker = runtime / "portable.profile"
    marker.write_text("APILeakGuard portable profile\n", encoding="utf-8")
    zip_tree(PORTABLE, paths_under(runtime), lambda path: f"APILeakGuard-v1.0/{path.relative_to(runtime).as_posix()}")


def source_files():
    loose = [ROOT / name for name in ("README.md", "RELEASE-NOTES.md", "LICENSE",
                                     "THIRD-PARTY-NOTICES.md", "requirements-win-x64.lock", ".gitignore")]
    dirs = [ROOT / name for name in ("apileakguard", "assets", "fixtures", "scripts", "tests", "docs")]
    return [item for item in [*loose, *(file for folder in dirs for file in paths_under(folder))]
            if item.is_file() and "__pycache__" not in item.parts and item.suffix.lower() in
            {"", ".py", ".ps1", ".json", ".ndjson", ".yaml", ".yml", ".md", ".svg", ".ico", ".lock", ".docx", ".txt"}]


def finalize():
    runtime = DIST / "APILeakGuard-v1.0"
    sources = source_files()
    mapping = {file.relative_to(ROOT).as_posix(): hash_file(file) for file in sorted(sources)}
    revision = sha256(json.dumps(mapping, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    zip_tree(SOURCE, sources, lambda path: f"APILeakGuard-v1.0/{path.relative_to(ROOT).as_posix()}")
    artifacts = {"release/" + PORTABLE.name: hash_file(PORTABLE)}
    artifacts.update({path.relative_to(ROOT).as_posix(): hash_file(path)
                      for path in (runtime / "APILeakGuard.exe", runtime / "apileakguard-cli.exe")})
    details = {"version": VERSION, "architecture": "x64", "distribution": "portable ZIP",
               "windows_targets": ["Windows 10", "Windows 11"],
               "signing": "unsigned", "source_sha256": revision, "source_files": mapping,
               "sha256": artifacts}
    (RELEASE / "manifest.json").write_text(json.dumps(details, indent=2) + "\n", encoding="utf-8")
    (RELEASE / "SHA256SUMS.txt").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in artifacts.items()), encoding="utf-8")
    print(revision)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "finalize"))
    options = parser.parse_args()
    WORK.mkdir(parents=True, exist_ok=True)
    RELEASE.mkdir(exist_ok=True)
    (prepare if options.action == "prepare" else finalize)()
