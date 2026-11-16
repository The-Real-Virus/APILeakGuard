"""Read a selected policy source for manual mapping into structured rules."""
from pathlib import Path
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile

from .model import FILE_BYTES, InputError, local_path, read_input
from .privacy import mask_text

WORD_TEXT = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t"
WORD_PARAGRAPH = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p"


def chapters(file):
    file = Path(file)
    if not local_path(file):
        raise InputError("Select a policy source on a local drive.")
    if file.suffix.lower() == ".docx":
        if file.stat().st_size > FILE_BYTES:
            raise InputError("Policy source file exceeds the 8 MiB limit.")
        try:
            with ZipFile(file) as package:
                part = package.getinfo("word/document.xml")
                if part.file_size > FILE_BYTES or part.flag_bits & 1:
                    raise InputError("The Word policy source is oversized or encrypted.")
                with package.open(part) as source:
                    data = source.read(FILE_BYTES + 1)
                if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
                    raise InputError("The Word policy source contains an unsupported XML declaration.")
                root = ElementTree.fromstring(data)
        except (BadZipFile, KeyError, ElementTree.ParseError, RuntimeError):
            raise InputError("The Word policy source could not be read.") from None
        lines = ("".join(node.text or "" for node in item.iter(WORD_TEXT)) for item in root.iter(WORD_PARAGRAPH))
    elif file.suffix.lower() in {".txt", ".md"}:
        lines = read_input(file)[0].splitlines()
    else:
        raise InputError("Select a text, Markdown or Word policy source.")
    rows = [mask_text(line.strip())[:500] for line in lines if line.strip()]
    if not rows:
        raise InputError("The policy source contains no readable clauses.")
    if len(rows) > 500:
        raise InputError("Select a policy source with up to 500 paragraphs or lines.")
    return rows
