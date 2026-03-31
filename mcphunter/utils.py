"""Shared utilities for MCPHunter."""

from __future__ import annotations

import sys
from typing import Any


def cli_print(msg: str, **kwargs: Any) -> None:
    """Print to CLI. Separated from logging for testability."""
    print(msg, **kwargs)
