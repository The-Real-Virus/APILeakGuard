"""Opt-in live check. Never prints the key, provider text or raw provider errors."""
import argparse
import json
from pathlib import Path
import sys

from apileakguard.assistant import Assistant
from apileakguard.model import InputError
from apileakguard.providers import Gemini, ProviderError
from apileakguard.service import Workspace


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--key-file", type=Path, required=True)
    args.add_argument("--workspace", type=Path, required=True)
    args.add_argument("--fixture", type=Path, required=True)
    args.add_argument("--model", help="Test this discovered model first.")
    options = args.parse_args()
    try:
        with options.key_file.open("r", encoding="utf-8-sig") as source:
            key = source.read(8193).strip()
    except (OSError, UnicodeError):
        print('{"key_file":"missing or unreadable"}')
        return 4
    result = {"provider": "Gemini", "discovery": "pending", "explanation": "pending", "action": "pending"}
    try:
        adapter = Gemini(key)
        models = adapter.models()
        result["discovery"] = "passed" if models else "no compatible models"
        result["available_generate_content_models"] = len(models)
        candidates = sorted((model for model in models if model.startswith("gemini-") and "flash" in model
                             and not any(tag in model for tag in ("audio", "tts", "image", "live", "robotics"))),
                            key=lambda model: ("preview" in model, "lite" in model, model), reverse=False)
        if options.model in models:
            candidates = [options.model, *(model for model in candidates if model != options.model)]
        workspace = Workspace(options.workspace)
        run = workspace.analyze([options.fixture])
        if not run["findings"]:
            raise InputError("Synthetic fixture did not produce a finding.")
        assistant = Assistant(workspace, enabled=True)
        for model in candidates[:5]:
            result["model"] = model
            try:
                message = assistant.ask("Gemini", model, key, run["run_id"],
                                        "Explain the detected field exposure and how to check a fix. Use two short sentences.")
                if not message["explanation"]:
                    continue
                result["explanation"] = "passed"
                action = assistant.ask("Gemini", model, key, run["run_id"],
                                       "Call the approved local coverage tool with no arguments.", allow_coverage=True)
                if action["action"] == "review_coverage" and action["result"] == run["summary"]:
                    result["action"] = "passed"
                    result.pop("http_status", None)
                    print(json.dumps(result))
                    return 0
            except ProviderError as error:
                result["http_status"] = error.status
                if error.status in {0, 401, 403}:
                    break
            except InputError:
                result["action"] = "model returned no valid action"
        print(json.dumps(result))
        return 3
    except ProviderError as error:
        result["http_status"] = error.status
    except Exception:
        result["status"] = "Local validation or decoding failed."
    print(json.dumps(result))
    return 3


if __name__ == "__main__":
    sys.exit(main())
