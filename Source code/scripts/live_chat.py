"""Verify multi-turn text and a typed action against Gemini using synthetic messages."""
import argparse
import json
from pathlib import Path
from threading import Event

from apileakguard.assistant_chat import ask_chat
from apileakguard.model import InputError
from apileakguard.providers import Gemini, ProviderError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--model", default="gemini-3.5-flash")
    options = parser.parse_args()
    result = {"provider": "Gemini", "model": options.model}
    try:
        with options.key_file.open(encoding="utf-8-sig") as stream:
            key = stream.read(8193).strip()
        result["discovery"] = options.model in Gemini(key).models()
        messages = [("You", "Say Atlas as our fictional project name, in one sentence. Do not perform an app task.")]
        reply = ask_chat("Gemini", options.model, key, messages, None, Event())
        result["plain_reply"] = bool(reply.text) and not reply.action and not reply.text.lstrip().startswith(("{", "["))
        messages.extend((("Assistant", reply.text), ("You", "What was my fictional project's name? Answer plainly.")))
        reply = ask_chat("Gemini", options.model, key, messages, None, Event())
        result["follow_up"] = "atlas" in reply.text.lower() and not reply.action
        action = ask_chat("Gemini", options.model, key, [("You", "Please open the bundled sample evidence now.")], None, Event())
        result["action_proposal"] = action.action == "open_sample" and action.arguments == {}
    except ProviderError as error:
        result["provider_status"] = error.status
    except (InputError, OSError, UnicodeError):
        result["status"] = "Live chat check could not complete."
    print(json.dumps(result))
    return 0 if all(result.get(key) for key in ("discovery", "plain_reply", "follow_up", "action_proposal")) else 3


if __name__ == "__main__":
    raise SystemExit(main())
