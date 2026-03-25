from __future__ import annotations

import ctypes
import os
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Optional


class PythonUsageError(Exception):
    pass


class PythonUsage:
    CALLBACK = ctypes.CFUNCTYPE(ctypes.c_int)

    def __init__(
        self,
        dll_path: str = "PythonUsage.dll",
        *,
        python_runtime: Optional[Any] = None,
        debug: bool = False,
    ) -> None:
        self._lock = threading.RLock()
        self._python_runtime = python_runtime
        self._debug = bool(debug)

        self._callback_ref: Optional[ctypes._CFuncPtr] = None
        self._dispatcher_installed = False
        self._dispatcher_installing = False

        self._python_func: Optional[Callable[..., Any]] = None
        self._pending_args: tuple[Any, ...] = ()
        self._pending_kwargs: dict[str, Any] = {}
        self._last_python_result: Any = None
        self._last_error: Optional[BaseException] = None

        self._dll_dir_handle = None
        self._dll_path = self._resolve_dll_path(dll_path)
        self._dll = self._load_dll(self._dll_path)
        self._configure_signatures()

    def _log(self, msg: str) -> None:
        if self._debug:
            print(f"[PythonUsage] {msg}", flush=True)

    @staticmethod
    def _resolve_dll_path(dll_path: str) -> str:
        raw = os.fspath(dll_path)
        p = Path(raw)
        candidates: list[Path] = []

        if p.is_absolute():
            candidates.append(p)
        else:
            try:
                candidates.append(Path(__file__).resolve().parent / raw)
            except Exception:
                pass

            try:
                candidates.append(Path.cwd() / raw)
            except Exception:
                pass

            meipass = getattr(sys, "_MEIPASS", None)
            if meipass:
                try:
                    candidates.append(Path(meipass) / raw)
                except Exception:
                    pass

            candidates.append(Path(raw))

        seen: set[str] = set()
        for cand in candidates:
            try:
                resolved = cand.resolve(strict=False)
            except Exception:
                resolved = cand

            text = str(resolved)
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)

            if os.path.exists(text):
                return os.path.abspath(text)

        return os.path.abspath(raw)

    def _load_dll(self, dll_path: str):
        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"PythonUsage.dll not found: {dll_path}")

        dll_dir = os.path.dirname(dll_path)

        if os.name == "nt":
            try:
                if dll_dir and os.path.isdir(dll_dir):
                    self._dll_dir_handle = os.add_dll_directory(dll_dir)
            except Exception:
                self._dll_dir_handle = None

        try:
            return ctypes.CDLL(dll_path)
        except OSError as e:
            raise PythonUsageError(
                f"Failed to load {dll_path!r}. "
                f"The DLL may exist, but one of its dependencies may be missing. "
                f"Original error: {e}"
            ) from e

    def close(self) -> None:
        if self._dll_dir_handle is not None:
            try:
                self._dll_dir_handle.close()
            except Exception:
                pass
            self._dll_dir_handle = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _configure_signatures(self) -> None:
        self._dll.SetCallback.argtypes = [self.CALLBACK]
        self._dll.SetCallback.restype = ctypes.c_int

        self._dll.RunOnce.argtypes = []
        self._dll.RunOnce.restype = ctypes.c_int

        self._dll.RunMany.argtypes = [ctypes.c_int]
        self._dll.RunMany.restype = ctypes.c_int

        self._dll.StartWorker.argtypes = [ctypes.c_int]
        self._dll.StartWorker.restype = ctypes.c_int

        self._dll.StopWorker.argtypes = []
        self._dll.StopWorker.restype = ctypes.c_int

        self._dll.IsWorkerRunning.argtypes = []
        self._dll.IsWorkerRunning.restype = ctypes.c_int

        self._dll.GetCallCount.argtypes = []
        self._dll.GetCallCount.restype = ctypes.c_longlong

        self._dll.GetLastResult.argtypes = []
        self._dll.GetLastResult.restype = ctypes.c_int

        self._dll.ResetStats.argtypes = []
        self._dll.ResetStats.restype = None

        self._dll.GetPythonUsageVersion.argtypes = []
        self._dll.GetPythonUsageVersion.restype = ctypes.c_int

    def set_python_runtime(self, python_runtime: Optional[Any]) -> None:
        with self._lock:
            self._python_runtime = python_runtime

    def _in_parallelpython_callback(self) -> bool:
        rt = self._python_runtime
        if rt is None:
            return False

        checker = getattr(rt, "in_parallelpython_callback", None)
        if checker is None or not callable(checker):
            return False

        try:
            return bool(checker())
        except Exception:
            return False

    @staticmethod
    def _coerce_result_to_int(result: Any) -> int:
        if result is None:
            return 0
        if isinstance(result, bool):
            return int(result)
        if isinstance(result, int):
            return int(result)
        if isinstance(result, float):
            return int(result)
        return 1

    def _execute_current_function_direct(self) -> int:
        with self._lock:
            func = self._python_func
            args = self._pending_args
            kwargs = dict(self._pending_kwargs)

        if func is None:
            with self._lock:
                self._last_python_result = None
                self._last_error = None
            return 0

        try:
            result = func(*args, **kwargs)
        except BaseException as e:
            with self._lock:
                self._last_error = e
            raise

        with self._lock:
            self._last_python_result = result
            self._last_error = None

        return self._coerce_result_to_int(result)

    def _dispatcher_thunk(self) -> int:
        try:
            return self._execute_current_function_direct()
        except BaseException:
            return 0

    def _ensure_dispatcher_installed(self) -> None:
        with self._lock:
            if self._dispatcher_installed:
                return
            if self._dispatcher_installing:
                return

            if self._in_parallelpython_callback():
                self._log("Skipping SetCallback inside ParallelPython callback context")
                return

            self._dispatcher_installing = True

        try:
            callback = self.CALLBACK(self._dispatcher_thunk)
            result = self._dll.SetCallback(callback)
            if result != 1:
                raise PythonUsageError(
                    f"SetCallback failed while installing dispatcher: {result} "
                    f"(dll={self._dll_path})"
                )

            with self._lock:
                self._callback_ref = callback
                self._dispatcher_installed = True
                self._log("Dispatcher installed")
        finally:
            with self._lock:
                self._dispatcher_installing = False

    def version(self) -> int:
        return int(self._dll.GetPythonUsageVersion())

    def set_function(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        if not callable(func):
            raise TypeError("func must be callable")

        with self._lock:
            self._python_func = func
            self._pending_args = args
            self._pending_kwargs = dict(kwargs)

        if not self._in_parallelpython_callback():
            self._ensure_dispatcher_installed()

    def run_once(self) -> int:
        if self._in_parallelpython_callback():
            self._log("run_once using direct execution inside ParallelPython callback")
            return self._execute_current_function_direct()

        self._ensure_dispatcher_installed()
        if not self._dispatcher_installed:
            self._log("run_once dispatcher unavailable, falling back to direct execution")
            return self._execute_current_function_direct()

        result = int(self._dll.RunOnce())
        if result < 0:
            raise PythonUsageError(f"RunOnce failed with code {result}")
        return result

    def run_many(self, iterations: int) -> int:
        iterations = int(iterations)
        if iterations < 0:
            raise ValueError("iterations must be >= 0")

        if self._in_parallelpython_callback():
            self._log("run_many using direct execution inside ParallelPython callback")
            total = 0
            for _ in range(iterations):
                total += self._execute_current_function_direct()
            return total

        self._ensure_dispatcher_installed()
        if not self._dispatcher_installed:
            self._log("run_many dispatcher unavailable, falling back to direct execution")
            total = 0
            for _ in range(iterations):
                total += self._execute_current_function_direct()
            return total

        result = int(self._dll.RunMany(iterations))
        if result < 0:
            raise PythonUsageError(f"RunMany failed with code {result}")
        return result

    def start_worker(self, interval_ms: int = 0) -> int:
        if self._in_parallelpython_callback():
            raise PythonUsageError(
                "start_worker is not safe to call inside a ParallelPython callback thread"
            )

        self._ensure_dispatcher_installed()
        if not self._dispatcher_installed:
            raise PythonUsageError("Dispatcher is not installed")

        result = int(self._dll.StartWorker(int(interval_ms)))
        if result < 0:
            raise PythonUsageError(f"StartWorker failed with code {result}")
        return result

    def stop_worker(self) -> int:
        return int(self._dll.StopWorker())

    def is_worker_running(self) -> bool:
        return bool(self._dll.IsWorkerRunning())

    def get_call_count(self) -> int:
        return int(self._dll.GetCallCount())

    def get_last_result(self) -> int:
        return int(self._dll.GetLastResult())

    def get_last_python_result(self) -> Any:
        with self._lock:
            return self._last_python_result

    def get_last_error(self) -> Optional[BaseException]:
        with self._lock:
            return self._last_error

    def reset_stats(self) -> None:
        self._dll.ResetStats()

    def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        self.set_function(func, *args, **kwargs)
        self.run_once()

        err = self.get_last_error()
        if err is not None:
            raise err

        return self.get_last_python_result()

    def wrap_function(self, func: Callable[..., Any]) -> Callable[..., Any]:
        if not callable(func):
            raise TypeError("func must be callable")

        def wrapped(*args: Any, **kwargs: Any) -> Any:
            return self.call(func, *args, **kwargs)

        wrapped.__name__ = getattr(func, "__name__", "wrapped_python_usage")
        return wrapped