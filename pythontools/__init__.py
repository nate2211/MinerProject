from __future__ import annotations

import types

try:
    # Load the compiled extension that sits next to this file:
    #   giltools/_giltools.cp312-win_amd64.pyd
    from .giltools import (  # type: ignore[attr-defined]
        yield_no_gil,
        burn_no_gil,
        unhinge_process,
        start_cpu_boost,
        stop_cpu_boost,
        is_cpu_boost_running,
    )

    # ADDED: This line will print a confirmation message
    print("giltools: C++ extension loaded successfully.")

    # `wait_handle_no_gil` exists only on Windows build; import if present
    try:
        from ._giltools import wait_handle_no_gil  # type: ignore[attr-defined]
    except Exception:
        def wait_handle_no_gil(*_a, **_k):
            raise NotImplementedError("wait_handle_no_gil is only available on Windows builds.")

    __all__ = [
        "yield_no_gil",
        "burn_no_gil",
        "unhinge_process",
        "start_cpu_boost",
        "stop_cpu_boost",
        "is_cpu_boost_running",
        "wait_handle_no_gil",
    ]

except Exception as e:
    # ADDED: This line will print a failure message
    print(f"giltools: Failed to load C++ extension. Reason: {e}")

    # Clear, consistent failure mode if the extension can't load
    def _missing(*_a, **_k):
        raise ImportError(f"giltools C++ extension failed to load: {e}")

    # Create a dummy module-like object for introspection/testing
    _ext = types.ModuleType("giltools_missing")
    _ext.__dict__.update({
        "yield_no_gil": _missing,
        "burn_no_gil": _missing,
        "unhinge_process": _missing,
        "start_cpu_boost": _missing,
        "stop_cpu_boost": _missing,
        "is_cpu_boost_running": _missing,
        "wait_handle_no_gil": _missing,
    })

    yield_no_gil = _ext.yield_no_gil
    burn_no_gil = _ext.burn_no_gil
    unhinge_process = _ext.unhinge_process
    start_cpu_boost = _ext.start_cpu_boost
    stop_cpu_boost = _ext.stop_cpu_boost
    is_cpu_boost_running = _ext.is_cpu_boost_running
    wait_handle_no_gil = _ext.wait_handle_no_gil

    __all__ = [
        "yield_no_gil",
        "burn_no_gil",
        "unhinge_process",
        "start_cpu_boost",
        "stop_cpu_boost",
        "is_cpu_boost_running",
        "wait_handle_no_gil",
    ]