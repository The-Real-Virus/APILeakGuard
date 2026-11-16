"""Preview, apply and roll back a selected local JSON field removal."""
from dataclasses import dataclass
from difflib import unified_diff
from hashlib import sha256
import json
import os
from pathlib import Path
import re

from .credentials import dpapi
from .model import FILE_BYTES, InputError, local_path, parse_json, read_input
from .privacy import mask, mask_text
from .reports import atomic_write

FIELD = re.compile(r"^[\w-]+(?:\.[\w-]+)*$")
HASH = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Patch:
    root: Path
    relative: Path
    field: str
    before_hash: str
    after_hash: str
    diff: str


def target_file(root, relative):
    root = Path(root)
    if not local_path(root):
        raise InputError("Select a source directory on a local drive.")
    root = root.resolve(strict=True)
    relative = Path(relative)
    target = (root / relative).resolve(strict=True)
    if relative.is_absolute() or ".." in relative.parts or not target.is_relative_to(root):
        raise InputError("Select a local JSON file inside the approved source directory.")
    if target.suffix.lower() != ".json":
        raise InputError("The supported edit removes an object field from a JSON file.")
    return target


def formatted(value):
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def compute(root, relative, field):
    path = target_file(root, relative)
    if not FIELD.fullmatch(field):
        raise InputError("Enter a dot-separated object field path.")
    text, before_hash = read_input(path)
    before = parse_json(text)
    after = parse_json(text)
    parent = after
    keys = field.split(".")
    for key in keys[:-1]:
        if not isinstance(parent, dict) or key not in parent:
            raise InputError("Field path could not be found in the selected file.")
        parent = parent[key]
    if not isinstance(parent, dict) or keys[-1] not in parent:
        raise InputError("Field path could not be found in the selected file.")
    del parent[keys[-1]]
    output = formatted(after)
    after_hash = sha256(output.encode("utf-8")).hexdigest()
    safe_diff = "".join(unified_diff(formatted(mask(before)).splitlines(keepends=True),
                                     formatted(mask(after)).splitlines(keepends=True),
                                     fromfile=mask_text(str(relative)), tofile=mask_text(str(relative))))
    return Patch(Path(root).resolve(), Path(relative), field, before_hash, after_hash, safe_diff), output


def preview_patch(root, relative, field):
    return compute(root, relative, field)[0]


def backup_for(root, digest):
    if not HASH.fullmatch(digest):
        raise InputError("A valid preview SHA-256 is required.")
    return Path(root) / (digest + (".dpapi" if os.name == "nt" else ".backup"))


def apply_patch(patch, backup_root):
    current, output = compute(patch.root, patch.relative, patch.field)
    if current != patch:
        raise InputError("The source changed after preview. Review a new patch.")
    backup_root = Path(backup_root)
    backup_root.mkdir(parents=True, exist_ok=True)
    backup = backup_for(backup_root, patch.before_hash)
    target = target_file(patch.root, patch.relative)
    with target.open("rb") as stream:
        original = stream.read(FILE_BYTES + 1)
    if sha256(original).hexdigest() != patch.before_hash:
        raise InputError("The source changed after preview. Review a new patch.")
    if not backup.exists():
        contents = dpapi(original, True) if os.name == "nt" else original
        atomic_write(backup, contents)
    atomic_write(target, output, replace=True)
    return backup


def rollback(patch, backup):
    target = target_file(patch.root, patch.relative)
    if read_input(target)[1] != patch.after_hash:
        raise InputError("The target changed after apply. Review it before rollback.")
    with Path(backup).open("rb") as stream:
        contents = stream.read(FILE_BYTES + 4096)
    original = dpapi(contents, False) if Path(backup).suffix == ".dpapi" else contents
    if sha256(original).hexdigest() != patch.before_hash:
        raise InputError("Backup verification failed.")
    atomic_write(target, original, replace=True)


def restore_verified(root, relative, before_hash, applied_hash, backup_root):
    if not HASH.fullmatch(applied_hash):
        raise InputError("Provide the hash of the applied version.")
    patch = Patch(Path(root), Path(relative), "", before_hash, applied_hash, "")
    rollback(patch, backup_for(backup_root, before_hash))
