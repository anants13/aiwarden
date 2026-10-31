"""Extract text and tool calls from LLM API payloads.

Supports the wire formats open models are usually served with:
  * OpenAI-compatible: /v1/chat/completions, /v1/completions, /v1/responses
    (vLLM, llama.cpp server, LM Studio, Ollama /v1, Together, Groq, OpenRouter...)
  * Ollama native: /api/chat, /api/generate
  * Anthropic-style: /v1/messages
Streaming (SSE and NDJSON) is handled by StreamAccumulator.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Segment:
    role: str  # system | user | assistant | tool
    text: str


@dataclass
class ToolCall:
    name: str
    arguments: Any


@dataclass
class ModelOutput:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


# --------------------------------------------------------------------------- requests

def _content_text(content: Any) -> Iterator[tuple[str | None, str]]:
    """Yield (role_override, text) from a message content field of any format."""
    if isinstance(content, str):
        yield None, content
    elif isinstance(content, list):
        for part in content:
            if isinstance(part, str):
                yield None, part
            elif isinstance(part, dict):
                ptype = part.get("type")
                if ptype in ("text", "input_text", "output_text") and isinstance(part.get("text"), str):
                    yield None, part["text"]
                elif ptype == "tool_result":  # anthropic
                    for _, t in _content_text(part.get("content")):
                        yield "tool", t
                elif ptype == "tool_use":
                    yield "assistant", json.dumps(part.get("input"), default=str)


def request_segments(body: Any) -> list[Segment]:
    if not isinstance(body, dict):
        return []
    segs: list[Segment] = []

    system = body.get("system")
    if system is not None:
        segs += [Segment("system", t) for _, t in _content_text(system)]
    if isinstance(body.get("instructions"), str):  # responses API
        segs.append(Segment("system", body["instructions"]))

    msgs = body.get("messages")
    if msgs is None and isinstance(body.get("input"), list):  # responses API
        msgs = body["input"]
    if isinstance(msgs, list):
        for m in msgs:
            if not isinstance(m, dict):
                continue
            role = m.get("role") or ("tool" if m.get("type") == "function_call_output" else "user")
            if role in ("developer",):
                role = "system"
            if role in ("function", "ipython"):
                role = "tool"
            content = m.get("content", m.get("output"))
            for override, text in _content_text(content):
                segs.append(Segment(override or role, text))

    for key in ("prompt", "input"):
        v = body.get(key)
        if isinstance(v, str):
            segs.append(Segment("user", v))
        elif isinstance(v, list) and key == "prompt":
            segs += [Segment("user", s) for s in v if isinstance(s, str)]
    return [s for s in segs if s.text]


# --------------------------------------------------------------------------- responses

class StreamAccumulator:
    """Feed raw response bytes (JSON, SSE, or NDJSON); get a ModelOutput."""

    def __init__(self, max_bytes: int = 4_000_000):
        self.max_bytes = max_bytes
        self._buf = b""
        self._total = 0
        self._text: list[str] = []
        self._tools: dict[Any, dict[str, Any]] = {}
        self._tool_order: list[Any] = []
        self._raw_chunks: list[bytes] = []
        self._saw_line_json = False
        self.truncated = False

    # -- input
    def feed(self, chunk: bytes) -> None:
        if self._total >= self.max_bytes:
            self.truncated = True
            return
        chunk = chunk[: self.max_bytes - self._total]
        self._total += len(chunk)
        self._raw_chunks.append(chunk)
        self._buf += chunk
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            self._line(line)

    def _line(self, line: bytes) -> None:
        line = line.strip()
        if line.startswith(b"data:"):
            line = line[5:].strip()
        if not line or line == b"[DONE]" or not line.startswith(b"{"):
            return
        try:
            obj = json.loads(line)
        except ValueError:
            return
        self._saw_line_json = True
        self.add(obj)

    def finish(self) -> ModelOutput:
        if not self._saw_line_json:
            # Plain (non-streaming) JSON body, possibly pretty-printed over many lines.
            try:
                self.add(json.loads(b"".join(self._raw_chunks)))
            except ValueError:
                pass
        elif self._buf.strip():
            self._line(self._buf)
        self._buf = b""
        calls = []
        for key in self._tool_order:
            t = self._tools[key]
            args = t["args"] if t["args"] is not None else "".join(t["arg_parts"])
            calls.append(ToolCall(t["name"] or "?", args))
        return ModelOutput("".join(self._text), calls)

    # -- shape handling
    def _tool(self, key, name=None) -> dict[str, Any]:
        if key not in self._tools:
            self._tools[key] = {"name": None, "args": None, "arg_parts": []}
            self._tool_order.append(key)
        if name:
            self._tools[key]["name"] = name
        return self._tools[key]

    def add(self, obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        typ = obj.get("type")

        # OpenAI chat/completions (stream deltas or full message)
        for i, ch in enumerate(obj.get("choices") or []):
            if not isinstance(ch, dict):
                continue
            if isinstance(ch.get("text"), str):
                self._text.append(ch["text"])
            msg = ch.get("delta") or ch.get("message") or {}
            if isinstance(msg.get("content"), str):
                self._text.append(msg["content"])
            for j, tc in enumerate(msg.get("tool_calls") or []):
                fn = tc.get("function") or {}
                key = ("oa", i, tc.get("index", j))
                t = self._tool(key, fn.get("name"))
                args = fn.get("arguments")
                if isinstance(args, str):
                    t["arg_parts"].append(args)
                elif args is not None:
                    t["args"] = args

        # Ollama native
        if isinstance(obj.get("message"), dict) and "choices" not in obj:
            m = obj["message"]
            if isinstance(m.get("content"), str):
                self._text.append(m["content"])
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                t = self._tool(("ol", len(self._tool_order)), fn.get("name"))
                t["args"] = fn.get("arguments")
        if isinstance(obj.get("response"), str):
            self._text.append(obj["response"])

        # Anthropic (non-stream message)
        if typ == "message" and isinstance(obj.get("content"), list):
            for k, block in enumerate(obj["content"]):
                self._anthropic_block(("an", k), block)
        # Anthropic stream
        if typ == "content_block_start":
            self._anthropic_block(("an", obj.get("index")), obj.get("content_block") or {})
        elif typ == "content_block_delta":
            d = obj.get("delta") or {}
            if d.get("type") == "text_delta":
                self._text.append(d.get("text", ""))
            elif d.get("type") == "input_json_delta":
                self._tool(("an", obj.get("index")))["arg_parts"].append(d.get("partial_json", ""))

        # OpenAI Responses API
        if typ == "response.completed" and isinstance(obj.get("response"), dict):
            self._responses_output(obj["response"].get("output"))
        elif obj.get("object") == "response":
            self._responses_output(obj.get("output"))

    def _anthropic_block(self, key, block: dict) -> None:
        if block.get("type") == "text" and block.get("text"):
            self._text.append(block["text"])
        elif block.get("type") == "tool_use":
            t = self._tool(key, block.get("name"))
            if block.get("input"):
                t["args"] = block["input"]

    def _responses_output(self, output) -> None:
        for k, item in enumerate(output or []):
            if not isinstance(item, dict):
                continue
            if item.get("type") == "message":
                for _, text in _content_text(item.get("content")):
                    self._text.append(text)
            elif item.get("type") == "function_call":
                t = self._tool(("rs", k), item.get("name"))
                t["args"] = item.get("arguments")


def parse_response(body: bytes) -> ModelOutput:
    acc = StreamAccumulator()
    acc.feed(body)
    return acc.finish()
