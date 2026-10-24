"""URA SDK 1.0: real, capability-controlled host calls from trusted Python code.

The worker is crash containment, NOT an OS security sandbox. Direct Python file,
network and process APIs retain the user's operating-system permissions.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Iterator

__version__ = "1.0.0"
API_VERSION = 1
_transport = None

class UraError(RuntimeError):
    """A bounded host API request was rejected or failed."""

def _call(method: str, **params: Any) -> Any:
    if _transport is None:
        raise UraError("ura is available only inside an explicitly authorised URA worker")
    return _transport(method, params)

def address(value: int | str) -> str:
    number = int(value, 0) if isinstance(value, str) else value
    if not isinstance(number, int) or not 0 <= number < 2**64:
        raise ValueError("address must be an unsigned64-bit integer")
    return hex(number)

@dataclass(frozen=True)
class Instruction:
    data: dict[str, Any]
    @property
    def address(self) -> int: return int(self.data["address"], 16)
    @property
    def mnemonic(self) -> str: return self.data["mnemonic"]
    @property
    def operands(self) -> str: return self.data.get("operands", "")

@dataclass(frozen=True)
class Function:
    data: dict[str, Any]
    @property
    def address(self) -> int: return int(self.data["address"], 16)
    @property
    def name(self) -> str: return self.data["name"]
    def details(self) -> dict[str, Any]: return _call("function", address=address(self.address))
    def cfg(self, max_blocks: int = 128) -> dict[str, Any]: return _call("cfg", address=address(self.address), limit=max_blocks)
    def ir(self, *, ssa: bool = False, offset: int = 0, limit: int = 128) -> dict[str, Any]:
        return _call("ir", address=address(self.address), ssa=ssa, offset=offset, limit=limit)
    def dataflow(self) -> dict[str, Any]: return _call("dataflow", address=address(self.address))
    def pseudocode_page(self, offset: int = 0, limit: int = 128) -> dict[str, Any]:
        return _call("pseudocode", address=address(self.address), offset=offset, limit=limit)
    def pseudocode(self) -> str:
        """Return the first <=2,000 lines; reject truncation instead of hiding it."""
        result = self.pseudocode_page(limit=2000)
        if result.get("truncated") or result["returned"] < result["total"]: raise UraError("source exceeds2000 lines; use pseudocode_page")
        return "\n".join("    " * line["indent"] + line["text"] for line in result["lines"])
    def signature(self) -> dict[str, Any]: return _call("signature", address=address(self.address))
    def stack(self) -> dict[str, Any]: return _call("stack", address=address(self.address))
    def inferred_types(self) -> dict[str, Any]: return _call("types", address=address(self.address))
    def xrefs(self, direction: str = "outgoing", limit: int = 128) -> dict[str, Any]:
        return _call("xrefs", address=address(self.address), direction=direction, limit=limit)
    def symbolic(self, options: dict[str, Any] | None = None) -> AnalysisTask:
        return AnalysisTask(_call("symbolic", action="start", function=address(self.address), options=options or {})["session"])

class Transaction:
    """Atomic rename/comment transaction. No binary writes or patch history bypass."""
    def __init__(self) -> None: self.edits: list[dict[str, Any]] = []
    def __enter__(self) -> Transaction: return self
    def rename(self, function: Function | int, name: str) -> None:
        self.edits.append({"kind":"rename", "address":address(function.address if isinstance(function, Function) else function), "name":name})
    def comment(self, at: int, note: str, label: str | None = None) -> None:
        self.edits.append({"kind":"comment", "address":address(at), "note":note, "label":label})
    def signature(self, function: Function | int, signature: dict[str, Any]) -> None:
        self.edits.append({"kind":"signature","address":address(function.address if isinstance(function,Function) else function),"signature":signature})
    def stack_variable(self, function: Function | int, offset: int, *, name: str | None = None, ty: dict[str, Any] | None = None) -> None:
        self.edits.append({"kind":"stackVariable","address":address(function.address if isinstance(function,Function) else function),"offset":offset,"name":name,"ty":ty})
    def type_library(self, library: dict[str, Any]) -> None:
        self.edits.append({"kind":"typeLibrary","library":library})
    def __exit__(self, kind: Any, value: Any, traceback: Any) -> None:
        if kind is None and self.edits: _call("transaction", edits=self.edits)

class Project:
    def metadata(self) -> dict[str, Any]: return _call("metadata")
    def binary(self) -> Binary: return Binary(self.metadata())
    def symbols(self, offset: int = 0, limit: int = 128) -> list[Symbol]:
        return [Symbol(row) for row in _call("symbols", offset=offset, limit=limit)["symbols"]]
    def functions(self, *, offset: int = 0, limit: int = 128) -> Iterator[Function]:
        for item in _call("functions", offset=offset, limit=limit)["functions"]: yield Function(item)
    def function_at(self, at: int) -> Function:
        return Function(_call("function", address=address(at))["function"])
    def instructions(self, at: int, count: int = 64) -> list[Instruction]:
        return [Instruction(row) for row in _call("instructions", address=address(at), limit=count)["instructions"]]
    def read_bytes(self, at: int, length: int, *, space: str = "effective") -> bytes:
        """Static original/effective-file-image bytes only; no live memory mixing."""
        result = _call("bytes", address=address(at), length=length, space=space)
        return bytes(result["bytes"])
    def mapping(self, at: int) -> dict[str, Any]: return _call("mapping", address=address(at))
    def transaction(self) -> Transaction: return Transaction()
    def rename(self, function: Function | int, name: str) -> None:
        with self.transaction() as tx: tx.rename(function, name)
    def comment(self, at: int, note: str, label: str | None = None) -> None:
        with self.transaction() as tx: tx.comment(at, note, label)
    def export_json(self, destination: str, data: Any) -> dict[str, Any]:
        return _call("export", destination=destination, data=data)
    def type_library(self) -> dict[str, Any]: return _call("typeLibrary")
    def set_signature(self, function: Function | int, signature: dict[str, Any]) -> None:
        with self.transaction() as tx:tx.signature(function,signature)
    def set_stack_variable(self, function: Function | int, offset: int, *, name: str | None = None, ty: dict[str, Any] | None = None) -> None:
        with self.transaction() as tx:tx.stack_variable(function,offset,name=name,ty=ty)
    def set_type_library(self, library: dict[str, Any]) -> None:
        with self.transaction() as tx:tx.type_library(library)

@dataclass(frozen=True)
class AnalysisTask:
    session: str
    def status(self) -> dict[str, Any]: return _call("symbolic", action="status", session=self.session)
    def page(self, category: str, offset: int = 0, limit: int = 16) -> dict[str, Any]:
        return _call("symbolic", action="page", session=self.session, category=category, offset=offset, limit=limit)
    def cancel(self) -> dict[str, Any]: return _call("symbolic", action="cancel", session=self.session)
    def close(self) -> dict[str, Any]: return _call("symbolic", action="close", session=self.session)

@dataclass(frozen=True)
class EmulationSession:
    session: str
    @classmethod
    def create(cls, config: dict[str, Any]) -> EmulationSession:
        return cls(_call("emulation", action="create", config=config)["session"])
    def status(self) -> dict[str, Any]: return _call("emulation", action="status", session=self.session)
    def step(self, steps: int = 1) -> dict[str, Any]: return _call("emulation", action="step", session=self.session, steps=steps)
    def run(self, steps: int = 1000) -> dict[str, Any]: return _call("emulation", action="run", session=self.session, steps=steps)
    def memory(self, at: int, length: int) -> dict[str, Any]: return _call("emulation", action="memory", session=self.session, address=address(at), length=length)
    def trace(self, after: int = 0, limit: int = 32) -> dict[str, Any]: return _call("emulation", action="trace", session=self.session, after=after, limit=limit)
    def close(self) -> dict[str, Any]: return _call("emulation", action="close", session=self.session)

@dataclass(frozen=True)
class DebuggerSession:
    """Existing session only; this SDK does not grant launch/attach/live writes."""
    session: str
    def query(self, action: str, **params: Any) -> dict[str, Any]:
        return _call("debugger", action=action, session=self.session, **params)

def current_project() -> Project: return Project()
def emit_finding(title: str, at: int, explanation: str, *, category: str = "analysis", severity: str = "info",
                 confidence: str = "candidate", evidence: Any = None, related: list[int] | None = None) -> None:
    _call("finding", title=title, address=address(at), explanation=explanation, category=category,
          severity=severity, confidence=confidence, evidence=evidence, related=[address(v) for v in related or []])
def cancelled() -> bool: return bool(_call("cancelled"))

@dataclass(frozen=True)
class Segment:
    """A real file section; mapping and file sizes remain explicit in data."""
    data: dict[str, Any]
    @property
    def name(self) -> str: return self.data["name"]
    @property
    def address(self) -> int: return int(self.data["address"], 16)

@dataclass(frozen=True)
class Symbol:
    """Original file symbol, distinct from user function-name overrides."""
    data: dict[str, Any]
    @property
    def name(self) -> str: return self.data["name"]
    @property
    def address(self) -> int | None:
        value=self.data.get("address")
        return int(value,16) if value is not None else None

@dataclass(frozen=True)
class Binary:
    data: dict[str, Any]
    @property
    def info(self) -> dict[str, Any]: return self.data["binary"]
    @property
    def sections(self) -> list[Segment]: return [Segment(row) for row in self.data["sections"]]
    @property
    def imports(self) -> list[dict[str, Any]]: return self.data["imports"]
    @property
    def exports(self) -> list[dict[str, Any]]: return self.data["exports"]

__all__ = ["Project", "Binary", "Segment", "Symbol", "Function", "Instruction", "Transaction", "AnalysisTask", "EmulationSession", "DebuggerSession",
           "UraError", "current_project", "emit_finding", "cancelled", "API_VERSION", "__version__"]
