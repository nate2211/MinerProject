from __future__ import annotations

import atexit
import ctypes as C
import os
import sys
import threading
import time
import weakref
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Generic, Optional, TypeVar, Union, cast


class PythonRuntimeError(Exception):
    pass


R = TypeVar("R")

PYR_Handle = C.c_void_p
PYR_JobId = C.c_uint64

PYR_OK = 0
PYR_PENDING = 1
PYR_TIMEOUT = 2

PYR_INVALID_ARGUMENT = -1
PYR_NOT_FOUND = -2
PYR_QUEUE_FULL = -3
PYR_RESULT_TOO_LARGE = -4
PYR_INTERNAL_ERROR = -5
PYR_CANCELLED = -6
PYR_RUNTIME_STOPPING = -7
PYR_BUFFER_TOO_SMALL = -8
PYR_MAX_JOBS_REACHED = -9

PYR_TASK_ECHO = 1
PYR_TASK_UPPERCASE = 2
PYR_TASK_REVERSE = 3
PYR_TASK_XOR = 4
PYR_TASK_USER_BASE = 1000

WRAPPER_BUILD = "python_runtime_parallelpython_safe_v2"


class PYR_Config(C.Structure):
    _fields_ = [
        ("worker_threads", C.c_int32),
        ("max_jobs", C.c_int32),
        ("max_result_bytes", C.c_int32),
        ("queue_capacity", C.c_int32),
    ]


class PYR_JobInfo(C.Structure):
    _fields_ = [
        ("status", C.c_int32),
        ("done", C.c_uint8),
        ("cancelled", C.c_uint8),
        ("reserved0", C.c_uint8),
        ("reserved1", C.c_uint8),
        ("result_size", C.c_uint32),
    ]


class PYR_Stats(C.Structure):
    _fields_ = [
        ("submitted_jobs", C.c_uint64),
        ("completed_jobs", C.c_uint64),
        ("failed_jobs", C.c_uint64),
        ("cancelled_jobs", C.c_uint64),
        ("active_jobs", C.c_uint64),
        ("queued_jobs", C.c_uint64),
        ("allocated_result_bytes", C.c_uint64),
        ("peak_allocated_result_bytes", C.c_uint64),
    ]


if C.sizeof(PYR_Config) != 16:
    raise RuntimeError(f"PYR_Config size mismatch: expected 16, got {C.sizeof(PYR_Config)}")

if C.sizeof(PYR_JobInfo) != 12:
    raise RuntimeError(f"PYR_JobInfo size mismatch: expected 12, got {C.sizeof(PYR_JobInfo)}")

if C.sizeof(PYR_Stats) != 64:
    raise RuntimeError(f"PYR_Stats size mismatch: expected 64, got {C.sizeof(PYR_Stats)}")


@dataclass(frozen=True)
class JobInfo:
    status: int
    done: bool
    cancelled: bool
    result_size: int


@dataclass(frozen=True)
class RuntimeStats:
    submitted_jobs: int
    completed_jobs: int
    failed_jobs: int
    cancelled_jobs: int
    active_jobs: int
    queued_jobs: int
    allocated_result_bytes: int
    peak_allocated_result_bytes: int


@dataclass(frozen=True)
class JobResult:
    job_id: int
    status: int
    text: str
    data: bytes
    info: JobInfo


_SHUTTING_DOWN = False
_RUNTIME_REGISTRY: "weakref.WeakSet[PythonRuntime]" = weakref.WeakSet()


def _mark_shutting_down() -> None:
    global _SHUTTING_DOWN
    _SHUTTING_DOWN = True


atexit.register(_mark_shutting_down)


class PythonRuntimeJob:
    def __init__(self, runtime: "PythonRuntime", job_id: int) -> None:
        self._runtime: Optional["PythonRuntime"] = runtime
        self.job_id = int(job_id)
        self._released = False

    @property
    def released(self) -> bool:
        return self._released

    def _require_runtime(self) -> "PythonRuntime":
        rt = self._runtime
        if rt is None or rt.is_closed:
            raise PythonRuntimeError(
                f"Job {self.job_id} can no longer be used because the runtime is closed"
            )
        return rt

    def query(self) -> JobInfo:
        return self._require_runtime().query_job(self.job_id)

    def wait(self, timeout_ms: int = 0xFFFFFFFF) -> JobResult:
        return self._require_runtime().wait_job(self.job_id, timeout_ms=timeout_ms)

    def cancel(self) -> int:
        return self._require_runtime().cancel(self.job_id)

    def release(self) -> int:
        if self._released:
            return PYR_OK

        rt = self._runtime
        if rt is None:
            self._released = True
            return PYR_OK

        if rt.is_closed:
            self._released = True
            self._runtime = None
            return PYR_OK

        try:
            rc = rt.release_job(self.job_id)
        except PythonRuntimeError:
            self._released = True
            self._runtime = None
            return PYR_OK

        if rc in (PYR_OK, PYR_NOT_FOUND):
            self._released = True
            self._runtime = None

        return rc

    def __enter__(self) -> "PythonRuntimeJob":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.release()
        except Exception:
            pass


class PythonRuntimeCall(Generic[R]):
    """
    Safe gate-based callable wrapper.

    Flow:
      1) a real gate job is submitted to PythonRuntime.dll
      2) after that gate job completes, the Python callable runs in Python
      3) the callable result is returned to the caller

    This does not attempt to execute arbitrary Python callables inside native code.
    """

    def __init__(
        self,
        gate_job: PythonRuntimeJob,
        func: Callable[..., R],
        *,
        func_args: tuple[Any, ...] = (),
        func_kwargs: Optional[dict[str, Any]] = None,
        timeout_ms: int = 0xFFFFFFFF,
        name: Optional[str] = None,
    ) -> None:
        self._gate_job = gate_job
        self._func = func
        self._func_args = tuple(func_args)
        self._func_kwargs = dict(func_kwargs or {})
        self._timeout_ms = int(timeout_ms)
        self._name = name or getattr(func, "__name__", "callable")

        self._done = threading.Event()
        self._started = False
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._exc: Optional[BaseException] = None
        self._result: Optional[R] = None

    @property
    def name(self) -> str:
        return self._name

    def _run(self) -> None:
        try:
            self._gate_job.wait(timeout_ms=self._timeout_ms)
            self._result = self._func(*self._func_args, **self._func_kwargs)
        except BaseException as e:
            self._exc = e
        finally:
            try:
                self._gate_job.release()
            except BaseException as e:
                if self._exc is None:
                    self._exc = e
            self._done.set()

    def start(self) -> "PythonRuntimeCall[R]":
        with self._lock:
            if self._started:
                return self

            self._started = True
            self._thread = threading.Thread(
                target=self._run,
                name=f"PythonRuntimeCall:{self._name}",
                daemon=True,
            )
            self._thread.start()
            return self

    def wait(self, timeout: Optional[float] = None) -> R:
        self.start()
        if not self._done.wait(timeout):
            raise TimeoutError(f"Timed out waiting for call: {self._name}")
        if self._exc is not None:
            raise self._exc
        return self.result()

    def done(self) -> bool:
        return self._done.is_set()

    def exception(self) -> Optional[BaseException]:
        return self._exc

    def result(self) -> R:
        if not self._done.is_set():
            raise RuntimeError(f"Call not complete yet: {self._name}")
        if self._exc is not None:
            raise self._exc
        return cast(R, self._result)


class PythonRuntime:
    """
    Self-contained PythonRuntime wrapper.

    Important design:
      - only loads PythonRuntime.dll
      - does not load ParallelPython.dll
      - exposes stable native job APIs
      - exposes safe gate-based call helpers
      - exposes bridge-friendly zero-arg callback wrappers for use with
        ParallelPythonBridge.make_void_callback(...)
    """

    def __init__(
        self,
        dll_path: str = "PythonRuntime.dll",
        *,
        worker_threads: int = 4,
        max_jobs: int = 4096,
        max_result_bytes: int = 4 * 1024 * 1024,
        queue_capacity: int = 4096,
        start_on_first_use: bool = True,
        close_cancel_pending: bool = True,
        close_wait_timeout_s: float = 5.0,
        debug_calls: bool = False,
    ) -> None:
        self._lock = threading.RLock()
        self._calls_cv = threading.Condition(self._lock)

        self._closed = False
        self._closing = False
        self._tearing_down = False

        self._handle: Optional[int] = None
        self._dll_dir_handle = None

        self._active_calls = 0
        self._live_jobs: set[int] = set()

        self._start_on_first_use = bool(start_on_first_use)
        self._close_cancel_pending = bool(close_cancel_pending)
        self._close_wait_timeout_s = max(0.0, float(close_wait_timeout_s))
        self._debug_calls = bool(debug_calls)

        self._cfg = PYR_Config(
            int(worker_threads),
            int(max_jobs),
            int(max_result_bytes),
            int(queue_capacity),
        )

        self.dll_path = self._resolve_dll_path(dll_path)
        self._dll = self._load_dll(self.dll_path)
        self._bind_functions(self._dll)
        self._parallel_callback_tls = threading.local()
        _RUNTIME_REGISTRY.add(self)

    def _enter_parallelpython_callback(self) -> None:
        self._parallel_callback_tls.active = True

    def _exit_parallelpython_callback(self) -> None:
        self._parallel_callback_tls.active = False

    def in_parallelpython_callback(self) -> bool:
        return bool(getattr(self._parallel_callback_tls, "active", False))
    @property
    def is_closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def is_started(self) -> bool:
        with self._lock:
            return bool(self._handle) and not self._closed

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

    def _load_dll(self, path: str):
        path = os.path.abspath(os.fspath(path))
        if not os.path.exists(path):
            raise PythonRuntimeError(f"PythonRuntime.dll not found at: {path}")

        dll_dir = os.path.dirname(path)
        if os.name == "nt":
            try:
                if dll_dir and os.path.isdir(dll_dir):
                    self._dll_dir_handle = os.add_dll_directory(dll_dir)
            except Exception:
                self._dll_dir_handle = None

        try:
            return C.CDLL(path)
        except OSError as e:
            raise PythonRuntimeError(
                f"Failed to load {path!r}. "
                f"The DLL may exist, but one of its dependencies may be missing. "
                f"Original error: {e}"
            ) from e

    def _bind_functions(self, dll) -> None:
        dll.pyr_create.argtypes = [C.POINTER(PYR_Config)]
        dll.pyr_create.restype = PYR_Handle

        dll.pyr_destroy.argtypes = [PYR_Handle]
        dll.pyr_destroy.restype = None

        dll.pyr_submit.argtypes = [
            PYR_Handle,
            C.c_int32,
            C.POINTER(C.c_uint8),
            C.c_uint32,
        ]
        dll.pyr_submit.restype = PYR_JobId

        dll.pyr_query_job.argtypes = [
            PYR_Handle,
            PYR_JobId,
            C.POINTER(PYR_JobInfo),
        ]
        dll.pyr_query_job.restype = C.c_int32

        dll.pyr_wait_job.argtypes = [
            PYR_Handle,
            PYR_JobId,
            C.c_uint32,
            C.POINTER(PYR_JobInfo),
        ]
        dll.pyr_wait_job.restype = C.c_int32

        dll.pyr_copy_result.argtypes = [
            PYR_Handle,
            PYR_JobId,
            C.POINTER(C.c_uint8),
            C.c_uint32,
            C.POINTER(C.c_uint32),
        ]
        dll.pyr_copy_result.restype = C.c_int32

        dll.pyr_release_job.argtypes = [PYR_Handle, PYR_JobId]
        dll.pyr_release_job.restype = C.c_int32

        dll.pyr_cancel.argtypes = [PYR_Handle, PYR_JobId]
        dll.pyr_cancel.restype = C.c_int32

        dll.pyr_get_stats.argtypes = [PYR_Handle, C.POINTER(PYR_Stats)]
        dll.pyr_get_stats.restype = C.c_int32

        dll.pyr_get_last_error_copy.argtypes = [
            PYR_Handle,
            C.POINTER(C.c_char),
            C.c_uint32,
            C.POINTER(C.c_uint32),
        ]
        dll.pyr_get_last_error_copy.restype = C.c_int32

        dll.pyr_status_string.argtypes = [C.c_int32]
        dll.pyr_status_string.restype = C.c_char_p

    def _log(self, msg: str) -> None:
        if self._debug_calls:
            print(f"[PYR {WRAPPER_BUILD}] {msg}", flush=True)

    def _status_text(self, status: int) -> str:
        try:
            raw = self._dll.pyr_status_string(int(status))
            if raw:
                return raw.decode("utf-8", errors="replace")
        except Exception:
            pass
        return f"status={status}"

    def _check_usable_unlocked(
        self,
        *,
        require_started: bool,
        allow_while_closing: bool,
    ) -> None:
        if self._closed:
            raise PythonRuntimeError("PythonRuntime is closed")
        if self._tearing_down:
            raise PythonRuntimeError("PythonRuntime is tearing down")
        if self._closing and not allow_while_closing:
            raise PythonRuntimeError("PythonRuntime is closing")
        if require_started and not self._handle:
            raise PythonRuntimeError("PythonRuntime is not started")

    def _native_handle_unlocked(self) -> PYR_Handle:
        return PYR_Handle(self._handle)

    @contextmanager
    def _native_call(
        self,
        name: str,
        *,
        allow_while_closing: bool = False,
    ):
        with self._lock:
            self._check_usable_unlocked(
                require_started=True,
                allow_while_closing=allow_while_closing,
            )
            handle = self._native_handle_unlocked()
            self._active_calls += 1
            self._log(
                f"enter {name} "
                f"handle={int(handle.value or 0)} "
                f"active={self._active_calls} "
                f"live_jobs={len(self._live_jobs)} "
                f"thread={threading.get_ident()}"
            )

        try:
            yield handle
        finally:
            with self._lock:
                self._active_calls -= 1
                self._log(
                    f"leave {name} "
                    f"active={self._active_calls} "
                    f"live_jobs={len(self._live_jobs)} "
                    f"thread={threading.get_ident()}"
                )
                self._calls_cv.notify_all()

    @staticmethod
    def _coerce_bytes(
        payload: Optional[Union[bytes, bytearray, memoryview, str]]
    ) -> tuple[Optional[object], int, C.POINTER(C.c_uint8)]:
        if payload is None:
            return None, 0, C.POINTER(C.c_uint8)()

        if isinstance(payload, str):
            raw = payload.encode("utf-8")
        elif isinstance(payload, memoryview):
            raw = payload.tobytes()
        elif isinstance(payload, (bytes, bytearray)):
            raw = bytes(payload)
        else:
            raise TypeError("payload must be bytes, bytearray, memoryview, str, or None")

        if not raw:
            return None, 0, C.POINTER(C.c_uint8)()

        buf = (C.c_uint8 * len(raw)).from_buffer_copy(raw)
        ptr = C.cast(buf, C.POINTER(C.c_uint8))
        return buf, len(raw), ptr

    @staticmethod
    def _jobinfo_to_py(info: PYR_JobInfo) -> JobInfo:
        return JobInfo(
            status=int(info.status),
            done=bool(info.done),
            cancelled=bool(info.cancelled),
            result_size=int(info.result_size),
        )

    def _register_job_unlocked(self, job_id: int) -> None:
        self._live_jobs.add(int(job_id))
        self._calls_cv.notify_all()

    def _forget_job_unlocked(self, job_id: int) -> None:
        self._live_jobs.discard(int(job_id))
        self._calls_cv.notify_all()

    def _get_last_error_text_unlocked(self) -> str:
        if self._closed or not self._handle:
            return ""

        written = C.c_uint32(0)
        buf_size = 4096
        buf = C.create_string_buffer(buf_size)

        rc = self._dll.pyr_get_last_error_copy(
            self._native_handle_unlocked(),
            buf,
            C.c_uint32(buf_size),
            C.byref(written),
        )
        if rc != PYR_OK:
            return ""

        n = int(written.value)
        if n <= 0:
            return ""

        end = max(0, n - 1)
        return bytes(buf[:end]).decode("utf-8", errors="replace")

    def _raise_for_status_unlocked(self, rc: int, prefix: str) -> None:
        if rc == PYR_OK:
            return

        extra = ""
        try:
            extra = self._get_last_error_text_unlocked()
        except Exception:
            extra = ""

        text = self._status_text(rc)
        if extra:
            raise PythonRuntimeError(f"{prefix} failed: {text} ({extra})")
        raise PythonRuntimeError(f"{prefix} failed: {text}")

    def _copy_result_bytes(self, job_id: int, expected_size: int) -> bytes:
        if expected_size <= 0:
            return b""

        out = (C.c_uint8 * expected_size)()
        written = C.c_uint32(0)

        with self._native_call("pyr_copy_result", allow_while_closing=True) as handle:
            rc = self._dll.pyr_copy_result(
                handle,
                PYR_JobId(int(job_id)),
                out,
                C.c_uint32(expected_size),
                C.byref(written),
            )

        with self._lock:
            self._raise_for_status_unlocked(rc, "pyr_copy_result")

        n = int(written.value)
        if n < 0 or n > expected_size:
            raise PythonRuntimeError(
                f"pyr_copy_result returned invalid byte count: {n} > {expected_size}"
            )

        return bytes(out[:n])

    def load_probe(self) -> dict[str, Any]:
        return {
            "wrapper_build": WRAPPER_BUILD,
            "dll_path": self.dll_path,
            "dll_loaded": self._dll is not None,
            "started": self.is_started,
            "closed": self.is_closed,
            "status_ok": self.status_string(PYR_OK),
            "parallelpython_bridge_loaded": False,
            "parallelpython_safe_mode": True,
        }

    def supports_native_python_callbacks(self) -> bool:
        return False

    def supports_parallelpython_safe_calls(self) -> bool:
        return True

    def start(self) -> None:
        with self._lock:
            self._check_usable_unlocked(
                require_started=False,
                allow_while_closing=False,
            )

            if self._handle:
                return

            if _SHUTTING_DOWN:
                raise PythonRuntimeError("Interpreter shutdown in progress")

            handle = self._dll.pyr_create(C.byref(self._cfg))
            if not handle:
                raise PythonRuntimeError(
                    f"pyr_create failed for {self.dll_path!r}. "
                    f"Check DLL dependencies, bitness, and native startup."
                )

            self._handle = int(C.cast(handle, C.c_void_p).value)
            self._log(f"started handle={self._handle}")

    def _ensure_started(self) -> None:
        with self._lock:
            if self._handle:
                return
            if not self._start_on_first_use:
                raise PythonRuntimeError("PythonRuntime is not started")
        self.start()

    def _cleanup_loaded_only(self) -> None:
        if self._dll_dir_handle is not None:
            try:
                self._dll_dir_handle.close()
            except Exception:
                pass
            self._dll_dir_handle = None

    def _finalize_close(self, *, _from_atexit: bool) -> bool:
        with self._lock:
            if self._closed:
                return True
            if self._tearing_down:
                return False
            if self._active_calls != 0:
                return False

            self._tearing_down = True
            handle_value = self._handle
            live_jobs = list(self._live_jobs)

        try:
            if handle_value and not _from_atexit and not _SHUTTING_DOWN:
                raw_handle = PYR_Handle(handle_value)

                for job_id in live_jobs:
                    try:
                        self._dll.pyr_release_job(raw_handle, PYR_JobId(int(job_id)))
                    except Exception:
                        pass

                self._dll.pyr_destroy(raw_handle)
        finally:
            with self._lock:
                self._handle = None
                self._live_jobs.clear()
                self._closed = True
                self._closing = False
                self._tearing_down = False
                self._calls_cv.notify_all()

            self._cleanup_loaded_only()
            try:
                _RUNTIME_REGISTRY.discard(self)
            except Exception:
                pass

        return True

    def _maybe_finalize_close(self) -> bool:
        with self._lock:
            if not self._closing or self._closed:
                return False
        return self._finalize_close(_from_atexit=False)

    def submit(
        self,
        task_type: int,
        payload: Optional[Union[bytes, bytearray, memoryview, str]] = None,
    ) -> PythonRuntimeJob:
        self._ensure_started()
        backing, size, ptr = self._coerce_bytes(payload)

        with self._native_call("pyr_submit", allow_while_closing=False) as handle:
            job_id = self._dll.pyr_submit(
                handle,
                C.c_int32(int(task_type)),
                ptr,
                C.c_uint32(size),
            )

        _ = backing

        with self._lock:
            if int(job_id) == 0:
                extra = self._get_last_error_text_unlocked()
                if extra:
                    raise PythonRuntimeError(f"pyr_submit failed: {extra}")
                raise PythonRuntimeError("pyr_submit failed")

            self._register_job_unlocked(int(job_id))

        return PythonRuntimeJob(self, int(job_id))

    def query_job(self, job_id: int) -> JobInfo:
        self._ensure_started()
        info = PYR_JobInfo()

        with self._native_call("pyr_query_job", allow_while_closing=True) as handle:
            rc = self._dll.pyr_query_job(
                handle,
                PYR_JobId(int(job_id)),
                C.byref(info),
            )

        with self._lock:
            if rc not in (PYR_OK, PYR_PENDING):
                self._raise_for_status_unlocked(rc, "pyr_query_job")

        return self._jobinfo_to_py(info)

    def wait_job(self, job_id: int, timeout_ms: int = 0xFFFFFFFF) -> JobResult:
        self._ensure_started()
        info = PYR_JobInfo()

        with self._native_call("pyr_wait_job", allow_while_closing=True) as handle:
            rc = self._dll.pyr_wait_job(
                handle,
                PYR_JobId(int(job_id)),
                C.c_uint32(int(timeout_ms)),
                C.byref(info),
            )

        with self._lock:
            self._raise_for_status_unlocked(rc, "pyr_wait_job")

        py_info = self._jobinfo_to_py(info)
        data = self._copy_result_bytes(job_id, py_info.result_size)
        text = data.decode("utf-8", errors="replace")

        return JobResult(
            job_id=int(job_id),
            status=py_info.status,
            text=text,
            data=data,
            info=py_info,
        )

    def copy_result(self, job_id: int) -> bytes:
        info = self.query_job(job_id)
        if not info.done:
            raise PythonRuntimeError("Job is not done yet")
        return self._copy_result_bytes(job_id, info.result_size)

    def release_job(self, job_id: int) -> int:
        self._ensure_started()

        with self._native_call("pyr_release_job", allow_while_closing=True) as handle:
            rc = self._dll.pyr_release_job(
                handle,
                PYR_JobId(int(job_id)),
            )

        with self._lock:
            if rc == PYR_NOT_FOUND:
                self._forget_job_unlocked(int(job_id))
            else:
                self._raise_for_status_unlocked(rc, "pyr_release_job")
                self._forget_job_unlocked(int(job_id))

        self._maybe_finalize_close()
        return int(rc)

    def cancel(self, job_id: int) -> int:
        self._ensure_started()

        with self._native_call("pyr_cancel", allow_while_closing=True) as handle:
            rc = self._dll.pyr_cancel(
                handle,
                PYR_JobId(int(job_id)),
            )

        with self._lock:
            if rc not in (PYR_OK, PYR_CANCELLED, PYR_NOT_FOUND):
                self._raise_for_status_unlocked(rc, "pyr_cancel")

        self._maybe_finalize_close()
        return int(rc)

    def get_stats(self) -> RuntimeStats:
        self._ensure_started()
        stats = PYR_Stats()

        with self._native_call("pyr_get_stats", allow_while_closing=True) as handle:
            rc = self._dll.pyr_get_stats(
                handle,
                C.byref(stats),
            )

        with self._lock:
            self._raise_for_status_unlocked(rc, "pyr_get_stats")

        return RuntimeStats(
            submitted_jobs=int(stats.submitted_jobs),
            completed_jobs=int(stats.completed_jobs),
            failed_jobs=int(stats.failed_jobs),
            cancelled_jobs=int(stats.cancelled_jobs),
            active_jobs=int(stats.active_jobs),
            queued_jobs=int(stats.queued_jobs),
            allocated_result_bytes=int(stats.allocated_result_bytes),
            peak_allocated_result_bytes=int(stats.peak_allocated_result_bytes),
        )

    def get_last_error(self) -> str:
        with self._lock:
            return self._get_last_error_text_unlocked()

    def status_string(self, status: int) -> str:
        return self._status_text(status)

    def echo(self, text: str, *, timeout_ms: int = 0xFFFFFFFF) -> JobResult:
        job = self.submit(PYR_TASK_ECHO, text)
        try:
            return job.wait(timeout_ms=timeout_ms)
        finally:
            try:
                job.release()
            except Exception:
                pass

    def uppercase(self, text: str, *, timeout_ms: int = 0xFFFFFFFF) -> JobResult:
        job = self.submit(PYR_TASK_UPPERCASE, text)
        try:
            return job.wait(timeout_ms=timeout_ms)
        finally:
            try:
                job.release()
            except Exception:
                pass

    def reverse(self, text: str, *, timeout_ms: int = 0xFFFFFFFF) -> JobResult:
        job = self.submit(PYR_TASK_REVERSE, text)
        try:
            return job.wait(timeout_ms=timeout_ms)
        finally:
            try:
                job.release()
            except Exception:
                pass

    def xor(
        self,
        payload: Union[bytes, bytearray, memoryview, str],
        *,
        timeout_ms: int = 0xFFFFFFFF,
    ) -> JobResult:
        job = self.submit(PYR_TASK_XOR, payload)
        try:
            return job.wait(timeout_ms=timeout_ms)
        finally:
            try:
                job.release()
            except Exception:
                pass

    def submit_call(
        self,
        func: Callable[..., R],
        *func_args: Any,
        timeout_ms: int = 0xFFFFFFFF,
        gate_task: int = PYR_TASK_ECHO,
        gate_payload: Union[bytes, bytearray, memoryview, str] = b"__call_gate__",
        name: Optional[str] = None,
        autostart: bool = True,
        **func_kwargs: Any,
    ) -> PythonRuntimeCall[R]:
        if not callable(func):
            raise TypeError("func must be callable; pass my_func, not my_func()")

        if autostart:
            self._ensure_started()

        gate_job = self.submit(gate_task, gate_payload)
        return PythonRuntimeCall(
            gate_job,
            func,
            func_args=func_args,
            func_kwargs=func_kwargs,
            timeout_ms=timeout_ms,
            name=name,
        )

    def run_call(
        self,
        func: Callable[..., R],
        *func_args: Any,
        timeout_ms: int = 0xFFFFFFFF,
        gate_task: int = PYR_TASK_ECHO,
        gate_payload: Union[bytes, bytearray, memoryview, str] = b"__call_gate__",
        name: Optional[str] = None,
        **func_kwargs: Any,
    ) -> R:
        if not callable(func):
            raise TypeError("func must be callable; pass my_func, not my_func()")

        call = self.submit_call(
            func,
            *func_args,
            timeout_ms=timeout_ms,
            gate_task=gate_task,
            gate_payload=gate_payload,
            name=name,
            **func_kwargs,
        )
        return call.wait()

    def wrap_call(
        self,
        func: Callable[..., R],
        *,
        timeout_ms: int = 0xFFFFFFFF,
        gate_task: int = PYR_TASK_ECHO,
        gate_payload: Union[bytes, bytearray, memoryview, str] = b"__call_gate__",
        name: Optional[str] = None,
    ) -> Callable[..., R]:
        if not callable(func):
            raise TypeError("func must be callable; pass my_func, not my_func()")

        call_name = name or getattr(func, "__name__", "wrapped_call")

        def wrapped(*args: Any, **kwargs: Any) -> R:
            return self.run_call(
                func,
                *args,
                timeout_ms=timeout_ms,
                gate_task=gate_task,
                gate_payload=gate_payload,
                name=call_name,
                **kwargs,
            )

        wrapped.__name__ = call_name
        return wrapped

    def submit_void(
        self,
        func: Callable[..., None],
        *func_args: Any,
        timeout_ms: int = 0xFFFFFFFF,
        gate_task: int = PYR_TASK_ECHO,
        gate_payload: Union[bytes, bytearray, memoryview, str] = b"__void_gate__",
        name: Optional[str] = None,
        autostart: bool = True,
        **func_kwargs: Any,
    ) -> PythonRuntimeCall[None]:
        return self.submit_call(
            func,
            *func_args,
            timeout_ms=timeout_ms,
            gate_task=gate_task,
            gate_payload=gate_payload,
            name=name,
            autostart=autostart,
            **func_kwargs,
        )

    def run_void(
        self,
        func: Callable[..., None],
        *func_args: Any,
        timeout_ms: int = 0xFFFFFFFF,
        gate_task: int = PYR_TASK_ECHO,
        gate_payload: Union[bytes, bytearray, memoryview, str] = b"__void_gate__",
        name: Optional[str] = None,
        **func_kwargs: Any,
    ) -> None:
        self.run_call(
            func,
            *func_args,
            timeout_ms=timeout_ms,
            gate_task=gate_task,
            gate_payload=gate_payload,
            name=name,
            **func_kwargs,
        )

    def wrap_void(
        self,
        func: Callable[..., None],
        *,
        timeout_ms: int = 0xFFFFFFFF,
        gate_task: int = PYR_TASK_ECHO,
        gate_payload: Union[bytes, bytearray, memoryview, str] = b"__void_gate__",
        name: Optional[str] = None,
    ) -> Callable[..., None]:
        wrapped = self.wrap_call(
            func,
            timeout_ms=timeout_ms,
            gate_task=gate_task,
            gate_payload=gate_payload,
            name=name,
        )

        def wrapped_void(*args: Any, **kwargs: Any) -> None:
            wrapped(*args, **kwargs)

        wrapped_void.__name__ = getattr(wrapped, "__name__", "wrapped_void")
        return wrapped_void

    def wrap_parallel_callback(
            self,
            func: Callable[..., Any],
            *func_args: Any,
            timeout_ms: int = 0xFFFFFFFF,
            gate_task: int = PYR_TASK_ECHO,
            gate_payload: Union[bytes, bytearray, memoryview, str] = b"__parallelpython_callback_gate__",
            name: Optional[str] = None,
            auto_invoke_returned_callable: bool = True,
            **func_kwargs: Any,
    ) -> Callable[[], None]:
        """
        Return a zero-arg callable suitable for ParallelPythonBridge.make_void_callback().

        Important safety rule:
          - if already inside a ParallelPython callback thread, do NOT call back into
            PythonRuntime.dll via run_call/submit/pyr_submit
          - instead, execute the Python callable directly
        """
        if not callable(func):
            raise TypeError("func must be callable; pass make_job, not make_job()")

        callback_name = name or getattr(func, "__name__", "parallel_callback")

        def wrapped() -> None:
            if self.in_parallelpython_callback():
                result = func(*func_args, **func_kwargs)
            else:
                result = self.run_call(
                    func,
                    *func_args,
                    timeout_ms=timeout_ms,
                    gate_task=gate_task,
                    gate_payload=gate_payload,
                    name=callback_name,
                    **func_kwargs,
                )

            if auto_invoke_returned_callable and callable(result):
                result()

        wrapped.__name__ = callback_name
        return wrapped

    def wrap_parallel_void_factory(
        self,
        factory: Callable[..., Callable[[], None]],
        *factory_args: Any,
        timeout_ms: int = 0xFFFFFFFF,
        gate_task: int = PYR_TASK_ECHO,
        gate_payload: Union[bytes, bytearray, memoryview, str] = b"__parallelpython_factory_gate__",
        name: Optional[str] = None,
        **factory_kwargs: Any,
    ) -> Callable[[], None]:
        """
        Convenience wrapper for factories that return a zero-arg void callable.
        """
        return self.wrap_parallel_callback(
            factory,
            *factory_args,
            timeout_ms=timeout_ms,
            gate_task=gate_task,
            gate_payload=gate_payload,
            name=name,
            auto_invoke_returned_callable=True,
            **factory_kwargs,
        )

    def close(self, *, _from_atexit: bool = False) -> None:
        with self._lock:
            if self._closed:
                return

            self._closing = True
            handle_value = self._handle
            live_jobs = list(self._live_jobs)

            if not handle_value:
                self._closed = True
                self._closing = False
                self._tearing_down = False
                self._cleanup_loaded_only()
                try:
                    _RUNTIME_REGISTRY.discard(self)
                except Exception:
                    pass
                return

        if handle_value and self._close_cancel_pending and not _from_atexit and not _SHUTTING_DOWN:
            raw_handle = PYR_Handle(handle_value)
            for job_id in live_jobs:
                try:
                    self._dll.pyr_cancel(raw_handle, PYR_JobId(int(job_id)))
                except Exception:
                    pass

        deadline = None
        if self._close_wait_timeout_s > 0:
            deadline = time.monotonic() + self._close_wait_timeout_s

        with self._lock:
            while self._active_calls > 0:
                if deadline is None:
                    self._calls_cv.wait()
                    continue

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._log(
                        "close deferred: active native calls still running "
                        f"(active={self._active_calls}, live_jobs={len(self._live_jobs)})"
                    )
                    return
                self._calls_cv.wait(timeout=remaining)

        self._finalize_close(_from_atexit=_from_atexit)

    def __enter__(self) -> "PythonRuntime":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


if __name__ == "__main__":
    import json
    import traceback

    def _sample_add(a: int, b: int) -> int:
        return a + b

    def _sample_void(msg: str) -> None:
        print(f"[void] {msg}")

    runtime: Optional[PythonRuntime] = None

    try:
        print("=" * 80)
        print("PythonRuntime parallelpython-safe probe")
        print("=" * 80)

        runtime = PythonRuntime(
            dll_path="PythonRuntime.dll",
            worker_threads=2,
            max_jobs=256,
            max_result_bytes=1024 * 1024,
            queue_capacity=256,
            debug_calls=True,
        )

        print(json.dumps(runtime.load_probe(), indent=2, default=str))
        runtime.start()

        print("\n-- native tasks --")
        print("echo:", runtime.echo("hello runtime").text)
        print("uppercase:", runtime.uppercase("hello world").text)
        print("reverse:", runtime.reverse("abcdef").text)
        print("xor:", runtime.xor(b"\x01\x02\x03\x04").data.hex())

        print("\n-- safe callable path --")
        print("run_call(sample_add) =", runtime.run_call(_sample_add, 20, 22, name="sample_add"))

        wrapped_pow = runtime.wrap_call(lambda a, b: a ** b, name="wrapped_pow")
        print("wrap_call result =", wrapped_pow(2, 8))

        runtime.run_void(_sample_void, "run_void executed", name="sample_void")
        runtime.submit_void(_sample_void, "submit_void executed", name="sample_void_async").wait()

        print("\n-- parallel bridge friendly wrappers --")
        parallel_cb = runtime.wrap_parallel_void_factory(
            lambda: (lambda: _sample_void("parallel factory executed")),
            name="parallel_factory_test",
        )
        parallel_cb()

        print("\n-- stats --")
        print(runtime.get_stats())

        print("\nProbe completed successfully.")

    except Exception as exc:
        print(f"\nProbe failed: {type(exc).__name__}: {exc}")
        traceback.print_exc()
        sys.exit(1)

    finally:
        if runtime is not None:
            try:
                runtime.close()
            except Exception as close_exc:
                print(f"[close warning] {close_exc}")