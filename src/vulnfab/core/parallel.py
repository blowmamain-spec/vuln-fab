"""Fork-based parallel map for CPU-bound analysis (WP-10.4).

Workers inherit the parent's already-parsed state through ``fork`` (copy-on-write), so nothing
large is pickled; only small task ids go in and result lists come back. Where ``fork`` is not
available (Windows) or ``jobs`` is 1, the work simply runs serially with identical results.
"""

from __future__ import annotations

import multiprocessing as mp
from collections.abc import Callable, Sequence
from typing import Any, TypeVar

T = TypeVar("T")
R = TypeVar("R")

_SHARED: Any = None


def _call(args: tuple[Callable[[Any, Any], Any], Any]) -> Any:
    fn, item = args
    return fn(item, _SHARED)


def can_fork() -> bool:
    return "fork" in mp.get_all_start_methods()


def pmap(fn: Callable[[T, Any], R], items: Sequence[T], jobs: int, shared: Any) -> list[R]:
    """``[fn(item, shared) for item in items]``, in order, optionally across processes.

    ``fn`` must be a module-level function; ``shared`` is read-only inside workers.
    """
    global _SHARED  # noqa: PLW0603 - handed to forked workers
    _SHARED = shared
    try:
        if jobs <= 1 or len(items) < 2 or not can_fork():
            return [fn(item, shared) for item in items]
        context = mp.get_context("fork")
        workers = min(jobs, len(items))
        with context.Pool(workers) as pool:
            return pool.map(_call, [(fn, item) for item in items], chunksize=1)
    finally:
        _SHARED = None
