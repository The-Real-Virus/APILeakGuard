"""Bounded HTTPS adapters for OpenAI, Claude and Gemini."""
from dataclasses import dataclass
from http.client import HTTPException
import json
import re
import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import ProxyHandler, Request, build_opener

from .model import InputError, parse_json
from .privacy import mask_text
from .requests import NoRedirect

MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
MAX_REPLY = 2 * 1024 * 1024


@dataclass(frozen=True)
class Turn:
    text: str = ""
    action: str | None = None
    arguments: dict | None = None
    notice: str = ""


def tool_definitions(tool):
    return tool if isinstance(tool, list) else [tool]


class ProviderError(InputError):
    def __init__(self, status, message=None):
        self.status = status
        message = message or {
            400: "Provider rejected the model or request format.",
            401: "The provider rejected the key. Check the selected provider and reload a valid key.",
            403: "The provider denied access. Check that the key has permission for this model and API.",
            404: "This model is unavailable to your key. Use Discover chat models and choose another model.",
            429: "The provider reached a usage limit. Wait and try again or check your quota.",
            0: "The connection to the provider was interrupted. Check your internet connection and try again.",
        }.get(status, "Provider service returned an unsuccessful status.")
        if 500 <= status < 600:
            message = "The provider service returned an error. Wait a moment and try again."
        super().__init__(message + (f" HTTP {status}." if status else ""))


def https(method, url, headers, payload):
    opener = build_opener(ProxyHandler({}), NoRedirect())
    encoded = None if payload is None else json.dumps(payload, ensure_ascii=True).encode("ascii")
    request = Request(url, data=encoded, headers=headers, method=method)
    try:
        with opener.open(request, timeout=35 if method == "POST" else 15) as response:
            raw = response.read(MAX_REPLY + 1)
    except HTTPError as error:
        error.close()
        raise ProviderError(error.code) from None
    except (OSError, HTTPException, ValueError) as error:
        reason = error.reason if isinstance(error, URLError) else error
        message = None
        if isinstance(reason, TimeoutError):
            message = "The provider took too long to respond. Try again in a moment."
        elif isinstance(reason, ssl.SSLError):
            message = "Could not establish a secure connection to the provider. Check your network or proxy settings."
        elif isinstance(reason, socket.gaierror):
            message = "Could not find the provider on the network. Check your internet connection or DNS settings."
        raise ProviderError(0, message) from None
    if len(raw) > MAX_REPLY:
        raise InputError("Provider response exceeds the 2 MiB limit.")
    try:
        result = parse_json(raw.decode("utf-8"))
    except (UnicodeError, InputError):
        raise InputError("Provider response could not be decoded.") from None
    if not isinstance(result, dict):
        raise InputError("Provider response was not an object.")
    return result


class Adapter:
    base = ""

    def __init__(self, key, transport=https):
        if not key or len(key) > 8192 or not key.isascii() or any(char.isspace() for char in key):
            raise InputError("Enter a single valid provider key.")
        self._key = key
        self.transport = transport

    def headers(self):
        return {"Content-Type": "application/json", "Accept": "application/json"}

    def call(self, path, payload=None):
        return self.transport("GET" if payload is None else "POST", self.base + path, self.headers(), payload)

    def available(self, row):
        return True

    def model(self, value):
        value = value.removeprefix("models/")
        if not MODEL_ID.fullmatch(value) or self._key in value:
            raise InputError("Invalid model identifier.")
        return quote(value, safe="")

    def models(self):
        cursor = None
        output = []
        for _ in range(10):
            packet, rows, cursor = self.model_page(cursor)
            for row in rows:
                identifier = row.get("id", row.get("name", "")).removeprefix("models/")
                if MODEL_ID.fullmatch(identifier) and self._key not in identifier and self.available(row):
                    output.append(identifier)
            if not cursor:
                break
        return sorted(set(output))

    def chat_models(self):
        """Discovery is a list of candidates. A listed model can still reject generation."""
        return self.models()

    def ask(self, model, prompt, tool=None):
        if len(prompt) > 18000:
            raise InputError("Provider context is limited to 18,000 characters.")
        try:
            result = self.generate(self.model(model), mask_text(prompt, (self._key,)), tool)
            return Turn(mask_text(result.text, (self._key,)), result.action, result.arguments)
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as error:
            if isinstance(error, InputError):
                raise
            raise InputError("Provider response did not match the expected contract.") from None


class OpenAI(Adapter):
    base = "https://api.openai.com/v1"

    def headers(self):
        return {**super().headers(), "Authorization": "Bearer " + self._key}

    def model_page(self, _cursor):
        packet = self.call("/models")
        return packet, packet["data"], None

    def chat_models(self):
        specialized = ("audio", "realtime", "transcribe", "tts", "embedding", "image", "moderation")
        return [model for model in sorted(self.models(), reverse=True)
                if model.startswith(("gpt-", "o1", "o3", "o4")) and not any(word in model for word in specialized)]

    def generate(self, model, prompt, tool):
        payload = {"model": model, "input": prompt, "store": False, "max_output_tokens": 1600}
        if tool:
            payload.update(tools=[{"type": "function", **item, "strict": True} for item in tool_definitions(tool)],
                           tool_choice="auto" if isinstance(tool, list) else "required",
                           parallel_tool_calls=False)
        output = self.call("/responses", payload)["output"]
        for row in output:
            if row["type"] == "function_call":
                return Turn(action=row["name"], arguments=parse_json(row["arguments"]))
        return Turn("\n".join(part["text"] for row in output if row["type"] == "message"
                              for part in row["content"] if part["type"] == "output_text"))


class Claude(Adapter):
    base = "https://api.anthropic.com/v1"

    def headers(self):
        return {**super().headers(), "x-api-key": self._key, "anthropic-version": "2023-06-01"}

    def model_page(self, cursor):
        path = "/models" + ("?" + urlencode({"after_id": cursor}) if cursor else "")
        packet = self.call(path)
        return packet, packet["data"], packet.get("last_id") if packet.get("has_more") else None

    def generate(self, model, prompt, tool):
        payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 1600}
        if tool:
            choice = {"type": "auto"} if isinstance(tool, list) else {"type": "tool", "name": tool["name"]}
            payload.update(tools=[{"name": item["name"], "description": item["description"],
                                   "input_schema": item["parameters"]} for item in tool_definitions(tool)],
                           tool_choice={**choice, "disable_parallel_tool_use": True})
        output = self.call("/messages", payload)["content"]
        for row in output:
            if row["type"] == "tool_use":
                return Turn(action=row["name"], arguments=row["input"])
        return Turn("\n".join(row["text"] for row in output if row["type"] == "text"))


class Gemini(Adapter):
    base = "https://generativelanguage.googleapis.com/v1beta"

    def headers(self):
        return {**super().headers(), "x-goog-api-key": self._key}

    def model_page(self, cursor):
        path = "/models?" + urlencode({"pageSize": 100, **({"pageToken": cursor} if cursor else {})})
        packet = self.call(path)
        return packet, packet["models"], packet.get("nextPageToken")

    def available(self, row):
        return "generateContent" in row.get("supportedGenerationMethods", [])

    def chat_models(self):
        pattern = re.compile(r"gemini-(\d+)(?:\.(\d+))?-(flash|flash-lite|pro)(?:-\d{3})?$")
        candidates = [model for model in self.models() if pattern.fullmatch(model)]

        def preference(model):
            major, minor, family = pattern.fullmatch(model).groups()
            return (model == "gemini-3.5-flash", int(major), int(minor or 0), family == "flash", model)

        return sorted(candidates, key=preference, reverse=True)

    def generate(self, model, prompt, tool):
        payload = {"contents": [{"role": "user", "parts": [{"text": prompt}]}],
                   "generationConfig": {"maxOutputTokens": 1600}}
        if tool:
            declarations = [{"name": item["name"], "description": item["description"],
                             "parametersJsonSchema": item["parameters"]} for item in tool_definitions(tool)]
            choice = {"mode": "AUTO"} if isinstance(tool, list) else {
                "mode": "ANY", "allowedFunctionNames": [tool["name"]]}
            payload.update(tools=[{"functionDeclarations": declarations}],
                           toolConfig={"functionCallingConfig": choice})
        parts = self.call(f"/models/{model}:generateContent", payload)["candidates"][0]["content"]["parts"]
        for part in parts:
            if "functionCall" in part:
                call = part["functionCall"]
                return Turn(action=call["name"], arguments=call.get("args", {}))
        return Turn("\n".join(part["text"] for part in parts if "text" in part and not part.get("thought")))


PROVIDERS = {"OpenAI": OpenAI, "Claude": Claude, "Gemini": Gemini}
