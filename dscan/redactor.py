"""Redactor — strip sensitive data from agent traces.

The public entry point is :func:`redact`, which accepts a string, dict,
or list and returns a scrubbed version. Strings are replaced with a new
string; dicts and lists are scrubbed recursively and mutated in place
(and also returned for convenience). Dict *keys* are never redacted —
only values.

Detection combines explicit regular expressions for well-known secret
shapes (cloud keys, API tokens, emails, phones, SSNs, credit cards) with
a Shannon-entropy heuristic for arbitrary high-entropy secrets.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

__all__ = ["redact"]


# --------------------------------------------------------------------------
# Structured-pattern detectors, applied in order. Each entry is
# (compiled_regex, replacement).
# --------------------------------------------------------------------------

# JSON Web Tokens (e.g. Supabase anon keys): header.payload.signature, all
# base64url. Matched first so its dots/length never reach later passes.
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)

# AWS access key IDs: AKIA + 16 uppercase alphanumerics.
_AWS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# Provider API tokens. Anthropic/OpenAI project keys carry internal
# dashes, so they are listed before the generic ``sk-`` fallback.
_API_KEY_RES = (
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]+"),          # Anthropic
    re.compile(r"\bsk-proj-[A-Za-z0-9_-]+"),         # OpenAI project
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{6,}"),      # GitHub tokens
    re.compile(r"\b[sprk]k_(?:live|test)_[A-Za-z0-9]+"),  # Stripe
    re.compile(r"\bsk-[A-Za-z0-9]{16,}"),            # generic OpenAI
)

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# US phone numbers (optional +1, separators required). The lookarounds
# stop us from biting into a longer run of digits.
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)"
)

_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

# Candidate credit-card numbers: 13-16 contiguous digits, Luhn-checked.
_CC_RE = re.compile(r"(?<!\d)\d{13,16}(?!\d)")

# UUIDs are high-entropy but are identifiers, not secrets — never redact.
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

# Whitespace-delimited tokens, for the entropy pass.
_TOKEN_RE = re.compile(r"\S+")

# Minimum length before a token is even considered a possible secret.
_MIN_SECRET_LEN = 16
# Shannon entropy (bits/char) above which a token looks random.
_ENTROPY_THRESHOLD = 3.5


def _shannon_entropy(text: str) -> float:
    """Return the Shannon entropy of ``text`` in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _luhn_ok(number: str) -> bool:
    """Return True if ``number`` (digits only) passes the Luhn checksum."""
    digits = [int(d) for d in number]
    parity = len(digits) % 2
    total = 0
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _looks_like_secret(token: str) -> bool:
    """Heuristic: does ``token`` look like an arbitrary high-entropy secret?

    Requires sufficient length, multiple character classes, and high
    Shannon entropy, while explicitly excluding identifiers (UUIDs),
    URLs, and filesystem paths that would otherwise score as random.
    """
    if len(token) < _MIN_SECRET_LEN:
        return False
    if _UUID_RE.fullmatch(token):
        return False
    if token.startswith(("http://", "https://")):
        return False
    if "/" in token:  # filesystem paths, URL-ish fragments
        return False

    classes = 0
    if re.search(r"[a-z]", token):
        classes += 1
    if re.search(r"[A-Z]", token):
        classes += 1
    if re.search(r"[0-9]", token):
        classes += 1
    # "Special" excludes - and _, which appear in benign hyphenated names.
    if re.search(r"[^A-Za-z0-9_-]", token):
        classes += 1
    if classes < 3:
        return False

    return _shannon_entropy(token) > _ENTROPY_THRESHOLD


def _redact_credit_cards(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        return "[REDACTED:CREDIT_CARD]" if _luhn_ok(match.group(0)) else match.group(0)

    return _CC_RE.sub(repl, text)


def _redact_secrets(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        token = match.group(0)
        return "[REDACTED:SECRET]" if _looks_like_secret(token) else token

    return _TOKEN_RE.sub(repl, text)


def _redact_string(text: str) -> str:
    """Scrub a single string, applying detectors most-specific first."""
    text = _JWT_RE.sub("[REDACTED:API_KEY]", text)
    text = _AWS_RE.sub("[REDACTED:AWS_KEY]", text)
    for pattern in _API_KEY_RES:
        text = pattern.sub("[REDACTED:API_KEY]", text)
    text = _EMAIL_RE.sub("[REDACTED:EMAIL]", text)
    text = _redact_credit_cards(text)
    text = _SSN_RE.sub("[REDACTED:SSN]", text)
    text = _PHONE_RE.sub("[REDACTED:PHONE]", text)
    text = _redact_secrets(text)
    return text


def redact(obj: Any) -> Any:
    """Redact sensitive data from ``obj``.

    - ``str`` -> a new, scrubbed string.
    - ``dict`` -> values scrubbed recursively, mutated in place, returned.
      Keys are left untouched.
    - ``list`` -> elements scrubbed recursively, mutated in place, returned.
    - anything else (int, float, bool, None, ...) -> returned unchanged.
    """
    if isinstance(obj, str):
        return _redact_string(obj)
    if isinstance(obj, dict):
        for key, value in obj.items():
            obj[key] = redact(value)
        return obj
    if isinstance(obj, list):
        for i, value in enumerate(obj):
            obj[i] = redact(value)
        return obj
    return obj
