"""Shared heuristics about column/field names."""

from __future__ import annotations

import re

SENSITIVE_NAME = re.compile(
    r"(passw(or)?d|passwd|secret|token|api_?key|private_?key|ssn|credit_?card|card_?number|cvv|otp)",
    re.IGNORECASE,
)
