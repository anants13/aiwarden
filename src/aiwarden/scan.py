"""Static scanner for model files. Nothing is ever loaded or executed.

Checks:
  * pickle-based weights (.bin .pt .pth .ckpt .pkl .joblib, torch zip archives):
    lists every imported global and flags code-execution gadgets.
  * Hugging Face repos: `auto_map` (requires trust_remote_code) and bundled .py files.
  * Chat templates (GGUF metadata, tokenizer_config.json): Jinja sandbox-escape markers.
  * safetensors: header sanity check.
"""

from __future__ import annotations

import io
import json
import pickletools
import re
import struct
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .events import Severity

PICKLE_EXTS = {".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib", ".dat", ".data", ".npy", ".model"}

SAFE_GLOBALS: dict[str, set[str] | str] = {
    "collections": {"OrderedDict", "defaultdict", "Counter", "deque"},
    "torch._utils": "*",
    "torch": {
        "Size", "device", "dtype", "FloatStorage", "HalfStorage", "BFloat16Storage", "DoubleStorage",
        "LongStorage", "IntStorage", "ShortStorage", "CharStorage", "ByteStorage", "BoolStorage",
        "ComplexFloatStorage", "ComplexDoubleStorage", "QInt8Storage", "QUInt8Storage", "QInt32Storage",
        "float32", "float16", "bfloat16", "float64", "int64", "int32", "int16", "int8", "uint8", "bool",
        "complex64", "complex128", "float8_e4m3fn", "float8_e5m2",
    },
    "torch.storage": {"UntypedStorage", "TypedStorage"},
    "torch.serialization": {"_get_layout"},
    "numpy": {"ndarray", "dtype"},
    "numpy.core.multiarray": {"_reconstruct", "scalar"},
    "numpy._core.multiarray": {"_reconstruct", "scalar"},
    "numpy.dtypes": "*",
    "builtins": {"set", "frozenset", "slice", "range", "complex", "bytearray", "bytes", "int", "float",
                 "str", "list", "dict", "tuple", "bool", "object"},
    "__builtin__": {"set", "frozenset", "slice", "complex", "bytearray", "int", "float", "list", "dict", "tuple", "bool", "object"},
    "_codecs": {"encode"},
    "argparse": {"Namespace"},
    "datetime": {"datetime", "date", "timedelta", "timezone"},
    "decimal": {"Decimal"},
}

DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "pty", "runpy", "importlib",
    "ctypes", "webbrowser", "requests", "urllib", "urllib2", "http", "httplib", "ftplib", "telnetlib",
    "smtplib", "asyncio", "multiprocessing", "code", "codeop", "pdb", "bdb", "timeit", "commands",
    "marshal", "types", "pickle", "_pickle", "cPickle", "dill", "cloudpickle", "shelve", "pip",
    "setuptools", "distutils", "tempfile", "pathlib", "glob", "_io", "io", "fileinput", "zipimport",
    "torch.hub", "torch.jit", "torch.package", "numpy.testing", "operator", "functools", "inspect",
    "uuid", "signal", "threading", "_thread", "aiohttp", "httpx", "paramiko", "Crypto", "base64",
    "zlib", "sqlite3", "logging.config",
}
DANGEROUS_BUILTINS = {
    "eval", "exec", "execfile", "compile", "open", "__import__", "getattr", "setattr", "delattr",
    "globals", "locals", "vars", "input", "breakpoint", "help", "apply", "memoryview", "type",
}

SSTI = re.compile(
    rb"__globals__|__builtins__|__subclasses__|__import__|__mro__|__base__|__init__\.|"
    rb"\.popen\(|subprocess|os\.system|cycler\.__|joiner\.__|lipsum\.|namespace\.__|"
    rb"request\.application|config\.__class__|get_flashed_messages"
)


@dataclass
class ScanFinding:
    path: str
    rule: str
    severity: Severity
    title: str
    detail: str = ""


# --------------------------------------------------------------------------- pickle

def _classify(module: str, name: str) -> Severity | None:
    """None = safe; otherwise a severity."""
    allowed = SAFE_GLOBALS.get(module)
    if allowed == "*" or (isinstance(allowed, set) and name in allowed):
        return None
    root = module.split(".")[0]
    if module in ("builtins", "__builtin__", "__builtins__"):
        return Severity.HIGH if name in DANGEROUS_BUILTINS else Severity.MEDIUM
    if module in DANGEROUS_MODULES or root in DANGEROUS_MODULES or any(
        module.startswith(d + ".") for d in DANGEROUS_MODULES
    ):
        return Severity.HIGH
    return Severity.MEDIUM


_STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
               "SHORT_BINSTRING", "BINSTRING", "STRING"}


def pickle_globals(data: bytes, max_pickles: int = 64) -> tuple[list[tuple[str, str]], str | None]:
    """Return (module, name) pairs imported by a (possibly multi-part) pickle stream."""
    found: list[tuple[str, str]] = []
    stream = io.BytesIO(data)
    error = None
    for _ in range(max_pickles):
        pos = stream.tell()
        if pos >= len(data):
            break
        strings: list[str] = []
        memo: dict = {}
        memo_count = 0
        prev = ""
        try:
            for op, arg, _p in pickletools.genops(stream):
                n = op.name
                last_was_str = prev in _STRING_OPS
                prev = n
                if n in _STRING_OPS:
                    strings.append(arg if isinstance(arg, str) else str(arg))
                elif n in ("BINPUT", "LONG_BINPUT", "PUT"):
                    if last_was_str:
                        memo[arg] = strings[-1]
                elif n == "MEMOIZE":
                    if last_was_str:
                        memo[memo_count] = strings[-1]
                    memo_count += 1
                elif n in ("BINGET", "LONG_BINGET", "GET") and arg in memo:
                    strings.append(memo[arg])
                elif n in ("GLOBAL", "INST"):
                    mod, _, nm = str(arg).partition(" ")
                    found.append((mod, nm))
                elif n == "STACK_GLOBAL":
                    if len(strings) >= 2:
                        found.append((strings[-2], strings[-1]))
                    else:
                        found.append(("?", "?"))
                elif n == "STOP":
                    break
        except Exception as exc:
            # Legacy torch files append raw tensor bytes after the pickles.
            if not found:
                error = f"{type(exc).__name__}: {exc}"
            break
        if stream.tell() == pos:
            break
    return found, error


def _is_pickle(head: bytes) -> bool:
    return len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5


def _scan_pickle_bytes(label: str, data: bytes) -> list[ScanFinding]:
    globs, err = pickle_globals(data)
    out: list[ScanFinding] = []
    if err and not globs:
        return [ScanFinding(label, "scan.pickle_parse_error", Severity.LOW, "Could not fully parse pickle", err)]
    dangerous = sorted({f"{m}.{n}" for m, n in globs if _classify(m, n) == Severity.HIGH})
    unknown = sorted({f"{m}.{n}" for m, n in globs if _classify(m, n) == Severity.MEDIUM})
    if dangerous:
        out.append(ScanFinding(label, "scan.pickle_dangerous_import", Severity.HIGH,
                               "Pickle imports code-execution capable callables. Do NOT load this file",
                               ", ".join(dangerous[:20])))
    if unknown:
        out.append(ScanFinding(label, "scan.pickle_unknown_import", Severity.MEDIUM,
                               "Pickle imports non-allowlisted globals (review before loading)",
                               ", ".join(unknown[:20]) + (" ..." if len(unknown) > 20 else "")))
    if not out:
        out.append(ScanFinding(label, "scan.pickle_format", Severity.LOW,
                               "Pickle-based weights (no dangerous imports found; prefer .safetensors)",
                               f"{len(globs)} globals, all allowlisted"))
    return out


def scan_pickle_file(path: Path) -> list[ScanFinding]:
    with path.open("rb") as fh:
        head = fh.read(4)
    if zipfile.is_zipfile(path):
        out: list[ScanFinding] = []
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.filename.endswith((".pkl", ".pickle")) or info.filename.endswith("/data"):
                    if info.file_size > 512 * 1024 * 1024:
                        continue
                    data = zf.read(info)
                    if _is_pickle(data[:2]):
                        out += _scan_pickle_bytes(f"{path}!{info.filename}", data)
        return out
    if _is_pickle(head) or path.suffix in (".pkl", ".pickle"):
        size = path.stat().st_size
        with path.open("rb") as fh:
            data = fh.read(min(size, 256 * 1024 * 1024))
        return _scan_pickle_bytes(str(path), data)
    return []


# --------------------------------------------------------------------------- other formats

def scan_safetensors(path: Path) -> list[ScanFinding]:
    try:
        with path.open("rb") as fh:
            (n,) = struct.unpack("<Q", fh.read(8))
            if n > 100 * 1024 * 1024:
                raise ValueError(f"header length {n} too large")
            json.loads(fh.read(n))
    except Exception as exc:
        return [ScanFinding(str(path), "scan.safetensors_invalid", Severity.MEDIUM, "Malformed safetensors header", str(exc))]
    return []


def _template_findings(label: str, blob: bytes) -> list[ScanFinding]:
    m = SSTI.search(blob)
    if m:
        return [ScanFinding(label, "scan.template_injection", Severity.HIGH,
                            "Chat template contains Jinja sandbox-escape markers (possible code execution)",
                            m.group(0).decode(errors="replace"))]
    return []


def scan_gguf(path: Path) -> list[ScanFinding]:
    with path.open("rb") as fh:
        if fh.read(4) != b"GGUF":
            return [ScanFinding(str(path), "scan.gguf_invalid", Severity.MEDIUM, "File has .gguf extension but no GGUF magic")]
        head = fh.read(64 * 1024 * 1024)  # metadata (incl. chat template) precedes tensors
    idx = head.find(b"tokenizer.chat_template")
    if idx < 0:
        return []
    return _template_findings(f"{path} (chat_template)", head[idx: idx + 512 * 1024])


def scan_hf_json(path: Path) -> list[ScanFinding]:
    out: list[ScanFinding] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return out
    if not isinstance(data, dict):
        return out
    if data.get("auto_map"):
        out.append(ScanFinding(str(path), "scan.trust_remote_code", Severity.HIGH,
                               "Model requires trust_remote_code=True (runs Python from the model repo)",
                               json.dumps(data["auto_map"])[:300]))
    tmpl = data.get("chat_template")
    if tmpl:
        blob = json.dumps(tmpl).encode()
        out += _template_findings(f"{path} (chat_template)", blob)
    return out


def iter_files(target: Path) -> Iterator[Path]:
    if target.is_file():
        yield target
        return
    for p in sorted(target.rglob("*")):
        if p.is_file() and ".git" not in p.parts:
            yield p


def scan_path(target: str | Path) -> list[ScanFinding]:
    target = Path(target).expanduser()
    if not target.exists():
        raise FileNotFoundError(target)
    findings: list[ScanFinding] = []
    py_files: list[str] = []
    for p in iter_files(target):
        suf = p.suffix.lower()
        try:
            if suf == ".safetensors":
                findings += scan_safetensors(p)
            elif suf == ".gguf":
                findings += scan_gguf(p)
            elif suf == ".py":
                py_files.append(p.name)
            elif p.name in ("config.json", "tokenizer_config.json"):
                findings += scan_hf_json(p)
            elif suf in PICKLE_EXTS or zipfile.is_zipfile(p):
                findings += scan_pickle_file(p)
            else:
                with p.open("rb") as fh:
                    if _is_pickle(fh.read(2)):
                        findings += scan_pickle_file(p)
        except Exception as exc:
            findings.append(ScanFinding(str(p), "scan.error", Severity.LOW, "Could not scan file", str(exc)))
    if py_files:
        findings.append(ScanFinding(str(target), "scan.bundled_code", Severity.MEDIUM,
                                    "Model directory contains Python files (executed if loaded with trust_remote_code)",
                                    ", ".join(py_files[:20])))
    return findings
