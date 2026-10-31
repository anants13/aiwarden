import collections
import json
import os
import pickle
import struct
import zipfile

from aiwarden.events import Severity
from aiwarden.scan import pickle_globals, scan_path


class Evil:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


def rules(findings):
    return {f.rule for f in findings}


def test_malicious_pickle_flagged(tmp_path):
    p = tmp_path / "pytorch_model.bin"
    p.write_bytes(pickle.dumps({"w": Evil()}, protocol=4))
    f = scan_path(p)
    assert "scan.pickle_dangerous_import" in rules(f)
    assert any(x.severity == Severity.HIGH and "system" in x.detail for x in f)


def test_protocol2_global_opcode(tmp_path):
    p = tmp_path / "m.pkl"
    p.write_bytes(pickle.dumps(Evil(), protocol=2))
    assert "scan.pickle_dangerous_import" in rules(scan_path(p))


def test_safe_pickle_is_low(tmp_path):
    p = tmp_path / "state.pt"
    p.write_bytes(pickle.dumps(collections.OrderedDict(a=[1, 2], b={1, 2}), protocol=4))
    f = scan_path(p)
    assert rules(f) == {"scan.pickle_format"}


def test_torch_zip_archive(tmp_path):
    p = tmp_path / "model.pt"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps(Evil(), protocol=2))
        zf.writestr("archive/data/0", b"\x00" * 16)
    f = scan_path(p)
    assert "scan.pickle_dangerous_import" in rules(f)
    assert "archive/data.pkl" in f[0].path


def test_memoized_stack_global_names():
    globs, _ = pickle_globals(pickle.dumps(Evil(), protocol=4))
    assert ("posix", "system") in globs or ("nt", "system") in globs


def test_trust_remote_code_and_bundled_py(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps({"auto_map": {"AutoModel": "modeling_x.XModel"}}))
    (tmp_path / "modeling_x.py").write_text("import os")
    r = rules(scan_path(tmp_path))
    assert {"scan.trust_remote_code", "scan.bundled_code"} <= r


def test_chat_template_ssti(tmp_path):
    (tmp_path / "tokenizer_config.json").write_text(json.dumps({
        "chat_template": "{{ cycler.__init__.__globals__.os.popen('id').read() }}"
    }))
    assert "scan.template_injection" in rules(scan_path(tmp_path))


def test_gguf_template(tmp_path):
    p = tmp_path / "m.gguf"
    p.write_bytes(b"GGUF" + b"\x03\x00\x00\x00" + b"tokenizer.chat_template" + b"{{ ''.__class__.__mro__[1].__subclasses__() }}")
    assert "scan.template_injection" in rules(scan_path(p))
    clean = tmp_path / "ok.gguf"
    clean.write_bytes(b"GGUF" + b"tokenizer.chat_template" + b"{% for m in messages %}{{ m.content }}{% endfor %}")
    assert scan_path(clean) == []


def test_safetensors(tmp_path):
    header = json.dumps({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    good = tmp_path / "good.safetensors"
    good.write_bytes(struct.pack("<Q", len(header)) + header + b"\x00" * 4)
    bad = tmp_path / "bad.safetensors"
    bad.write_bytes(struct.pack("<Q", 10) + b"not json!!")
    assert scan_path(good) == []
    assert rules(scan_path(bad)) == {"scan.safetensors_invalid"}
