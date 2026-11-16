"""Queries over masked evidence and findings."""
from datetime import datetime
import shlex

from .model import canonical

FILTERS = {"api", "project", "environment", "route", "method", "role", "source", "status", "severity",
           "kind", "before", "after", "request_id"}


def parse_query(query):
    try:
        words = shlex.split(query, posix=True)
    except ValueError:
        return query, {}
    terms, filters = [], {}
    for word in words:
        key, separator, value = word.partition(":")
        if separator and key.lower() in FILTERS and value:
            filters[key.lower()] = value
        else:
            terms.append(word)
    return " ".join(terms), filters


def matches(row, term, filters):
    endpoint = row.get("endpoint") or ()
    values = dict(zip(("project", "api", "environment", "method", "route", "role", "status", "variant"), endpoint))
    values.update(row)
    for key, expected in filters.items():
        if key in {"before", "after"}:
            try:
                actual = datetime.fromisoformat(values.get("timestamp") or "")
                boundary = datetime.fromisoformat(expected)
                if actual.tzinfo is None or boundary.tzinfo is None:
                    actual, boundary = actual.replace(tzinfo=None), boundary.replace(tzinfo=None)
                if (key == "before" and actual > boundary) or (key == "after" and actual < boundary):
                    return False
            except (ValueError, TypeError):
                return False
        elif str(values.get(key) or "").casefold() != str(expected).casefold():
            return False
    return term.casefold() in canonical(row).casefold()
