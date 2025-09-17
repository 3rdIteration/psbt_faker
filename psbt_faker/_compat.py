"""Compatibility helpers for legacy dependencies."""

from __future__ import annotations

import inspect
from collections import namedtuple
from typing import Any, Callable


ArgSpec = namedtuple("ArgSpec", "args varargs keywords defaults")


def ensure_pycoin_compat() -> None:
    """Backport :func:`inspect.getargspec` for older ``pycoin`` releases."""

    if hasattr(inspect, "getargspec"):
        return

    def _getargspec(func: Callable[..., Any]) -> ArgSpec:  # pragma: no cover - exercised via import
        spec = inspect.getfullargspec(func)
        return ArgSpec(spec.args, spec.varargs, spec.varkw, spec.defaults)

    inspect.getargspec = _getargspec  # type: ignore[attr-defined]


__all__ = ["ensure_pycoin_compat"]

