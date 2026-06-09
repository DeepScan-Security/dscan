"""dscan shield — a prompt-injection firewall for agent tool calls.

``ShieldMiddleware`` scans text crossing trust boundaries (user input,
model output, and especially content coming back from tools) for prompt
injection and jailbreak attempts. It combines two layers: an always-on
set of regular-expression patterns that catch obvious attacks offline,
and (when online) Meta's LlamaFirewall models (PromptGuard /
AlignmentCheck) for learned detection.

LlamaFirewall is imported lazily and treated as an optional extra: with
``offline=True`` the regex layer runs alone, and if the models are not
downloaded an online scan raises :class:`ModelNotReadyError` pointing the
user at ``dscan shield --setup`` rather than a raw HuggingFace traceback.
The watcher calls :meth:`ShieldMiddleware.shield_check` before each tool
runs and refuses to execute a blocked call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Literal

__all__ = [
    "ShieldResult",
    "ShieldBlockedError",
    "ModelNotReadyError",
    "ShieldMiddleware",
]

Mode = Literal["input", "output", "both", "tool_results"]
Source = Literal["input", "output", "tool_result", "system_prompt"]

_MODEL_NOT_READY_MSG = (
    "dscan shield requires model download. Run: dscan shield --setup"
)

# Which sources each mode actually scans. "system_prompt" is always trusted
# and never scanned, regardless of mode.
_MODE_SOURCES: dict[str, set[str]] = {
    "input": {"input"},
    "output": {"output"},
    "both": {"input", "output", "tool_result"},
    "tool_results": {"tool_result"},
}

# Always-on regex layer. Active even when online (as a fallback after the
# model passes) and the sole detector when offline.
_OFFLINE_PATTERNS = [
    r"ignore\s+(previous|prior|all)\s+instructions?",
    r"\[INST\]|\[\/INST\]",
    r"you\s+are\s+now\s+(DAN|jailbroken|free)",
    r"(system\s*prompt|instructions?).*reveal",
    r"ignore\s+your\s+(system\s*)?(prompt|instructions?)",
    r"pretend\s+you\s+(have\s+no|are\s+not)",
]


@dataclass
class ShieldResult:
    """The outcome of scanning one piece of text."""

    blocked: bool
    reason: str | None
    scanner: str | None  # "PromptGuard" | "AlignmentCheck" | "custom" | "regex"
    confidence: float  # 0.0–1.0
    input_text: str  # truncated to 200 chars for logging
    category: str | None = None  # "injection" | "jailbreak" | "custom" | None


class ShieldBlockedError(Exception):
    """Raised when a tool call is blocked by the shield."""


class ModelNotReadyError(Exception):
    """Raised when an online scan is attempted but models are not present."""


def _iter_strings(obj: Any) -> Iterator[str]:
    """Yield every string leaf in ``obj`` (recursing dicts/lists)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from _iter_strings(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            yield from _iter_strings(value)


def _clean(text: str) -> ShieldResult:
    return ShieldResult(False, None, None, 0.0, text[:200], None)


class ShieldMiddleware:
    """Scans text for prompt injection and gates tool execution."""

    def __init__(
        self,
        mode: Mode = "both",
        custom_rules: list[str] | None = None,
        offline: bool = False,
        model_dir: str | None = None,
    ) -> None:
        self.mode = mode
        self.offline = offline
        self.model_dir = (
            Path(model_dir) if model_dir else Path.home() / ".dscan" / "models"
        )
        self._mode_sources = _MODE_SOURCES.get(mode, _MODE_SOURCES["both"])
        self._custom_rules = [re.compile(p, re.IGNORECASE) for p in (custom_rules or [])]
        self._offline_patterns = [re.compile(p, re.IGNORECASE) for p in _OFFLINE_PATTERNS]
        self._firewall: Any | None = None

    # ------------------------------------------------------------------
    # Public scanning API
    # ------------------------------------------------------------------
    def scan(self, text: str, source: str = "input") -> ShieldResult:
        """Scan ``text`` and return a :class:`ShieldResult` immediately."""
        text = text or ""
        truncated = text[:200]

        # System prompts are trusted and never scanned.
        if source == "system_prompt":
            return _clean(text)
        # Out of scope for this mode -> pass.
        if source not in self._mode_sources:
            return _clean(text)

        # 1) Custom regex rules.
        for pattern in self._custom_rules:
            if pattern.search(text):
                return ShieldResult(
                    True, f"matched: {pattern.pattern}", "custom", 1.0, truncated, "custom"
                )

        # 2) Model layer (online only). Runs before the regex fallback so a
        #    real detection is attributed to the model.
        if not self.offline:
            result = self._model_scan(text, source)
            if result is not None:
                return result

        # 3) Always-on regex layer.
        for pattern in self._offline_patterns:
            if pattern.search(text):
                return ShieldResult(
                    True,
                    "prompt injection pattern detected",
                    "regex",
                    0.9,
                    truncated,
                    "injection",
                )

        return _clean(text)

    def scan_tool_result(self, tool_name: str, result: dict) -> ShieldResult:
        """Scan every string in a tool result; return the first block."""
        for value in _iter_strings(result):
            scanned = self.scan(value, source="tool_result")
            if scanned.blocked:
                return scanned
        return ShieldResult(False, None, None, 0.0, "", None)

    def shield_check(self, tool_name: str, params: dict) -> ShieldResult:
        """Scan all string values in ``params`` before a tool executes."""
        for value in _iter_strings(params):
            scanned = self.scan(value, source="input")
            if scanned.blocked:
                return scanned
        return ShieldResult(False, None, None, 0.0, "", None)

    # ------------------------------------------------------------------
    # Model layer (LlamaFirewall) — the mockable boundary
    # ------------------------------------------------------------------
    def _model_scan(self, text: str, source: str) -> ShieldResult | None:
        firewall = self._get_firewall()
        verdict = firewall.scan(text, source)
        return self._verdict_to_result(verdict, text)

    def _verdict_to_result(self, verdict: Any, text: str) -> ShieldResult | None:
        decision = getattr(verdict, "decision", verdict)
        if "BLOCK" not in str(decision).upper():
            return None
        scanner = getattr(verdict, "scanner", None) or "PromptGuard"
        reason = getattr(verdict, "reason", None) or "prompt injection detected"
        score = getattr(verdict, "score", None)
        confidence = float(score) if isinstance(score, (int, float)) else 0.9
        return ShieldResult(True, reason, scanner, confidence, text[:200], "injection")

    def _get_firewall(self) -> Any:
        if self._firewall is not None:
            return self._firewall
        if not self._models_present():
            raise ModelNotReadyError(_MODEL_NOT_READY_MSG)
        try:
            self._firewall = self._load_firewall()
        except ModelNotReadyError:
            raise
        except Exception as exc:  # noqa: BLE001 — convert cryptic HF errors
            raise ModelNotReadyError(_MODEL_NOT_READY_MSG) from exc
        return self._firewall

    def _models_present(self) -> bool:
        return self.model_dir.exists() and any(self.model_dir.iterdir())

    def _load_firewall(self) -> Any:  # pragma: no cover - needs llamafirewall + models
        from llamafirewall import (  # type: ignore
            LlamaFirewall,
            Role,
            ScannerType,
            UserMessage,
        )

        firewall = LlamaFirewall(scanners={Role.USER: [ScannerType.PROMPT_GUARD]})
        return _FirewallAdapter(firewall, UserMessage)

    # ------------------------------------------------------------------
    # Setup (model download)
    # ------------------------------------------------------------------
    def setup(self) -> None:
        """Download required models from HuggingFace with a progress bar."""
        from rich.console import Console
        from rich.progress import Progress

        console = Console()
        models = self._required_models()
        with Progress(console=console) as progress:
            task = progress.add_task("Downloading dscan shield models", total=len(models))
            for model_id in models:
                self._download_model(model_id)
                progress.advance(task)
        console.print("[green]✓[/green] dscan shield models ready.")

    def _required_models(self) -> list[str]:
        return ["meta-llama/Llama-Prompt-Guard-2-86M"]

    def _download_model(self, model_id: str) -> None:  # pragma: no cover - network
        from huggingface_hub import snapshot_download  # type: ignore

        target = self.model_dir / model_id.replace("/", "__")
        target.mkdir(parents=True, exist_ok=True)
        snapshot_download(repo_id=model_id, local_dir=str(target))


class _FirewallAdapter:  # pragma: no cover - needs llamafirewall + models
    """Adapts LlamaFirewall to the shield's ``scan(text, source)`` boundary."""

    def __init__(self, firewall: Any, message_cls: Any) -> None:
        self._firewall = firewall
        self._message_cls = message_cls

    def scan(self, text: str, source: str) -> Any:
        return self._firewall.scan(self._message_cls(content=text))
