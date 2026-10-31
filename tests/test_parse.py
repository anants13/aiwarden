import json

from aiwarden.gateway.parse import StreamAccumulator, parse_response, request_segments


def sse(*objs):
    return b"".join(b"data: " + json.dumps(o).encode() + b"\n\n" for o in objs) + b"data: [DONE]\n\n"


def test_request_segments_openai():
    body = {
        "model": "x",
        "messages": [
            {"role": "system", "content": "be nice"},
            {"role": "user", "content": [{"type": "text", "text": "hi"}, {"type": "image_url", "image_url": {}}]},
            {"role": "tool", "content": "tool output", "tool_call_id": "1"},
        ],
    }
    segs = [(s.role, s.text) for s in request_segments(body)]
    assert segs == [("system", "be nice"), ("user", "hi"), ("tool", "tool output")]


def test_request_segments_anthropic_tool_result_and_generate():
    body = {
        "system": "sys",
        "messages": [{"role": "user", "content": [{"type": "tool_result", "content": [{"type": "text", "text": "page"}]}]}],
    }
    assert [(s.role, s.text) for s in request_segments(body)] == [("system", "sys"), ("tool", "page")]
    assert [(s.role, s.text) for s in request_segments({"prompt": "p", "system": "s"})] == [("system", "s"), ("user", "p")]


def test_openai_non_stream_tool_call():
    body = json.dumps({
        "choices": [{"message": {"content": "ok", "tool_calls": [
            {"function": {"name": "sh", "arguments": "{\"cmd\": \"ls\"}"}}]}}]
    }, indent=2).encode()
    out = parse_response(body)
    assert out.text == "ok"
    assert out.tool_calls[0].name == "sh"
    assert json.loads(out.tool_calls[0].arguments) == {"cmd": "ls"}


def test_openai_stream_tool_call_deltas():
    body = sse(
        {"choices": [{"delta": {"content": "Hel"}}]},
        {"choices": [{"delta": {"content": "lo"}}]},
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "shell", "arguments": "{\"c"}}]}}]},
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "md\": \"id\"}"}}]}}]},
    )
    acc = StreamAccumulator()
    for i in range(0, len(body), 7):  # arbitrary chunk boundaries
        acc.feed(body[i:i + 7])
    out = acc.finish()
    assert out.text == "Hello"
    assert out.tool_calls[0].name == "shell"
    assert out.tool_calls[0].arguments == '{"cmd": "id"}'


def test_ollama_ndjson_stream():
    lines = [
        {"message": {"role": "assistant", "content": "a"}, "done": False},
        {"message": {"role": "assistant", "content": "", "tool_calls": [
            {"function": {"name": "run", "arguments": {"cmd": "whoami"}}}]}, "done": False},
        {"message": {"role": "assistant", "content": "b"}, "done": True},
    ]
    out = parse_response(b"\n".join(json.dumps(x).encode() for x in lines) + b"\n")
    assert out.text == "ab"
    assert out.tool_calls[0].arguments == {"cmd": "whoami"}


def test_ollama_generate():
    out = parse_response(b'{"response":"hi "}\n{"response":"there","done":true}\n')
    assert out.text == "hi there"


def test_anthropic_stream():
    body = b"".join([
        b"event: message_start\n",
        b'data: {"type":"message_start","message":{"content":[]}}\n\n',
        b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n',
        b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"yo"}}\n\n',
        b'data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","name":"bash","input":{}}}\n\n',
        b'data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\\"c\\":"}}\n\n',
        b'data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\\"ls\\"}"}}\n\n',
    ])
    out = parse_response(body)
    assert out.text == "yo"
    assert out.tool_calls[0].name == "bash"
    assert out.tool_calls[0].arguments == '{"c":"ls"}'


def test_responses_api_completed_event():
    body = sse({"type": "response.completed", "response": {"output": [
        {"type": "message", "content": [{"type": "output_text", "text": "done"}]},
        {"type": "function_call", "name": "f", "arguments": "{}"},
    ]}})
    out = parse_response(body)
    assert out.text == "done"
    assert out.tool_calls[0].name == "f"
