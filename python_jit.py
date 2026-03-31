from __future__ import annotations

import ctypes
import hashlib
import os
import threading
import time
from ctypes import (
    c_void_p,
    c_int,
    c_char_p,
    c_ubyte,
    c_uint32,
    POINTER,
    cast,
    byref,
    memmove,
)
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Any

from monero_job import MoneroJob
from python_usage import PythonUsage
from randomx_ctypes import RandomX
import sys
import heapq
class PythonJITError(RuntimeError):
    pass



@dataclass
class JITThunk:
    handle: int
    address: int
    kind: str
    _callback_ref: Any


class PythonJIT:
    # Exact native callback signature from the header:
    # typedef int (__cdecl* PJIT_TargetInt1)(void* user_data);
    # typedef void(__cdecl* PJIT_TargetVoid1)(void* user_data);
    INT_TARGET = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
    VOID_TARGET = ctypes.CFUNCTYPE(None, ctypes.c_void_p)

    def __init__(self, dll_path: str = "PythonJIT.dll") -> None:
        self.dll_path = self._resolve_dll_path(dll_path)
        self._dll_dir_handle = None
        self._dll = self._load_dll(self.dll_path)
        self._configure()
        self._thunks: list[JITThunk] = []

    def _resolve_dll_path(self, raw: str) -> str:
        candidates: list[Path] = []

        p = Path(raw)
        candidates.append(p)

        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / raw)

        candidates.append(Path(__file__).resolve().parent / raw)
        candidates.append(Path.cwd() / raw)
        candidates.append(Path(sys.executable).resolve().parent / raw)

        for cand in candidates:
            try:
                if cand.exists():
                    return str(cand.resolve())
            except Exception:
                continue
        return str(p)

    def _load_dll(self, path: str):
        if not os.path.exists(path):
            raise FileNotFoundError(f"PythonJIT.dll not found: {path}")

        dll_dir = os.path.dirname(path)
        if os.name == "nt":
            try:
                if dll_dir and os.path.isdir(dll_dir):
                    self._dll_dir_handle = os.add_dll_directory(dll_dir)
            except Exception:
                self._dll_dir_handle = None

        # Header uses __cdecl exports, so CDLL is correct.
        return ctypes.CDLL(path)

    def _configure(self) -> None:
        L = self._dll

        L.PJIT_GetVersion.argtypes = []
        L.PJIT_GetVersion.restype = ctypes.c_int

        L.PJIT_GetLastErrorA.argtypes = []
        L.PJIT_GetLastErrorA.restype = ctypes.c_char_p

        L.PJIT_ClearLastError.argtypes = []
        L.PJIT_ClearLastError.restype = None

        # Use ctypes-friendly raw address variants from the header.
        L.PJIT_CreateIntThunk0FromAddress.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
        L.PJIT_CreateIntThunk0FromAddress.restype = ctypes.c_void_p

        L.PJIT_CreateVoidThunk0FromAddress.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
        L.PJIT_CreateVoidThunk0FromAddress.restype = ctypes.c_void_p

        # Optional helpers for smoke testing Python callback addresses directly.
        L.PJIT_CallInt1Address.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
        L.PJIT_CallInt1Address.restype = ctypes.c_int

        L.PJIT_CallVoid1Address.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
        L.PJIT_CallVoid1Address.restype = None

        L.PJIT_IsProbablyExecutableAddress.argtypes = [ctypes.c_size_t]
        L.PJIT_IsProbablyExecutableAddress.restype = ctypes.c_int

        L.PJIT_GetThunkAddress.argtypes = [ctypes.c_void_p]
        L.PJIT_GetThunkAddress.restype = ctypes.c_void_p

        L.PJIT_InvokeIntThunk0.argtypes = [ctypes.c_void_p]
        L.PJIT_InvokeIntThunk0.restype = ctypes.c_int

        L.PJIT_InvokeVoidThunk0.argtypes = [ctypes.c_void_p]
        L.PJIT_InvokeVoidThunk0.restype = None

        L.PJIT_DestroyThunk.argtypes = [ctypes.c_void_p]
        L.PJIT_DestroyThunk.restype = ctypes.c_int

        L.PJIT_DestroyAllThunks.argtypes = []
        L.PJIT_DestroyAllThunks.restype = None

    def version(self) -> int:
        return int(self._dll.PJIT_GetVersion())

    def last_error(self) -> str:
        msg = self._dll.PJIT_GetLastErrorA()
        if not msg:
            return ""
        return msg.decode("utf-8", errors="replace")

    @staticmethod
    def _ptr_value(p: Any) -> int:
        return int(ctypes.cast(p, ctypes.c_void_p).value or 0)

    def _require_handle(self, handle: Any) -> int:
        value = self._ptr_value(handle)
        if not value:
            raise PythonJITError(self.last_error() or "JIT call failed")
        return value

    def _validate_python_target_addr(self, target_addr: int, *, user_data: int = 0) -> None:
        if target_addr == 0:
            raise PythonJITError("target callback address is null")

        try:
            is_exec = int(self._dll.PJIT_IsProbablyExecutableAddress(ctypes.c_size_t(target_addr)))
        except Exception:
            is_exec = 1

        if not is_exec:
            raise PythonJITError("Python callback address is not executable/committed")

        # Smoke test the raw callback address directly first.
        # This gives a much clearer failure point than creating a thunk immediately.
        rc = int(self._dll.PJIT_CallInt1Address(ctypes.c_size_t(target_addr), ctypes.c_size_t(user_data)))
        # If the callback ran and returned 1/0/etc that's fine. If native side trapped,
        # last_error() will be populated and rc is usually 0.
        err = self.last_error()
        if err:
            raise PythonJITError(err)

    def create_int_thunk0(self, func: Callable[[Any], int], user_data: Optional[int] = None) -> JITThunk:
        cb = self.INT_TARGET(func)
        target_addr = self._ptr_value(cb)
        user_data_addr = int(user_data or 0)

        self._dll.PJIT_ClearLastError()
        self._validate_python_target_addr(target_addr, user_data=user_data_addr)

        handle = self._require_handle(
            self._dll.PJIT_CreateIntThunk0FromAddress(
                ctypes.c_size_t(target_addr),
                ctypes.c_size_t(user_data_addr),
            )
        )
        addr = self._require_handle(self._dll.PJIT_GetThunkAddress(ctypes.c_void_p(handle)))

        thunk = JITThunk(handle=handle, address=addr, kind="int0", _callback_ref=cb)
        self._thunks.append(thunk)
        return thunk

    def create_void_thunk0(self, func: Callable[[Any], None], user_data: Optional[int] = None) -> JITThunk:
        cb = self.VOID_TARGET(func)
        target_addr = self._ptr_value(cb)
        user_data_addr = int(user_data or 0)

        self._dll.PJIT_ClearLastError()

        handle = self._require_handle(
            self._dll.PJIT_CreateVoidThunk0FromAddress(
                ctypes.c_size_t(target_addr),
                ctypes.c_size_t(user_data_addr),
            )
        )
        addr = self._require_handle(self._dll.PJIT_GetThunkAddress(ctypes.c_void_p(handle)))

        thunk = JITThunk(handle=handle, address=addr, kind="void0", _callback_ref=cb)
        self._thunks.append(thunk)
        return thunk

    def invoke_int0(self, thunk: JITThunk) -> int:
        self._dll.PJIT_ClearLastError()
        result = int(self._dll.PJIT_InvokeIntThunk0(ctypes.c_void_p(thunk.handle)))
        err = self.last_error()
        if err:
            raise PythonJITError(err)
        return result

    def invoke_void0(self, thunk: JITThunk) -> None:
        self._dll.PJIT_ClearLastError()
        self._dll.PJIT_InvokeVoidThunk0(ctypes.c_void_p(thunk.handle))
        err = self.last_error()
        if err:
            raise PythonJITError(err)

    def destroy(self, thunk: JITThunk) -> None:
        rc = int(self._dll.PJIT_DestroyThunk(ctypes.c_void_p(thunk.handle)))
        if rc != 0:
            raise PythonJITError(self.last_error() or f"DestroyThunk failed: {rc}")
        self._thunks = [x for x in self._thunks if x.handle != thunk.handle]

    def close(self) -> None:
        try:
            self._dll.PJIT_DestroyAllThunks()
        finally:
            self._thunks.clear()
            if self._dll_dir_handle is not None:
                try:
                    self._dll_dir_handle.close()
                except Exception:
                    pass
                self._dll_dir_handle = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class _JobDispatchCoordinator:
    """
    Self-contained coordinator so no external code changes are required.

    What it does:
    - auto-detects when the active job changes
    - bumps a generation so old work becomes stale
    - repairs repeated/backward/overlapping start_nonce requests by moving them
      onto the next safe nonce window
    - keeps a freshness clock for the active job
    """

    def __init__(self, *, hashed_job_start: bool = True) -> None:
        self._mu = threading.RLock()
        self._active_job_id: Optional[str] = None
        self._active_generation: int = 0
        self._job_started_at: float = 0.0
        self._next_nonce: int = 0
        self._hashed_job_start = bool(hashed_job_start)

    @staticmethod
    def _norm_job_id(job_id: str) -> str:
        return str(job_id)

    def _seed_nonce_for_job(self, job_id: str) -> int:
        if not self._hashed_job_start:
            return 0
        h = hashlib.blake2s(
            self._norm_job_id(job_id).encode("utf-8", "ignore"),
            digest_size=4,
        ).digest()
        return int.from_bytes(h, "little", signed=False) & 0xFFFFFFFF

    @staticmethod
    def _is_forward_or_equal(req: int, cur: int) -> bool:
        delta = (int(req) - int(cur)) & 0xFFFFFFFF
        return delta == 0 or delta < 0x80000000

    def observe_and_reserve(
        self,
        job_id: str,
        requested_start_nonce: int,
        count: int,
    ) -> tuple[int, int]:
        job_id = self._norm_job_id(job_id)
        count = max(1, int(count))
        req = int(requested_start_nonce) & 0xFFFFFFFF

        with self._mu:
            if self._active_job_id != job_id:
                next_gen = (self._active_generation + 1) & 0x7FFFFFFF
                if next_gen == 0:
                    next_gen = 1

                self._active_job_id = job_id
                self._active_generation = next_gen
                self._job_started_at = time.perf_counter()

                actual_start = req if req != 0 else self._seed_nonce_for_job(job_id)
                self._next_nonce = (actual_start + count) & 0xFFFFFFFF
                return actual_start, self._active_generation

            if self._is_forward_or_equal(req, self._next_nonce):
                actual_start = req
            else:
                actual_start = self._next_nonce

            self._next_nonce = (actual_start + count) & 0xFFFFFFFF
            return actual_start, self._active_generation

    def is_current(self, job_id: str, generation: int) -> bool:
        job_id = self._norm_job_id(job_id)
        generation = int(generation)
        with self._mu:
            return (
                self._active_job_id == job_id
                and self._active_generation == generation
            )

    def current_job_age_ms(self) -> float:
        with self._mu:
            if self._job_started_at <= 0.0:
                return 0.0
            return max(0.0, (time.perf_counter() - self._job_started_at) * 1000.0)

    def current_generation(self) -> int:
        with self._mu:
            return self._active_generation

    def current_job_id(self) -> Optional[str]:
        with self._mu:
            return self._active_job_id


class _CandidateSelector:
    """
    Keeps only unique legitimate candidates and ranks strongest-first.
    """

    def __init__(self, *, max_keep_default: int = 16) -> None:
        self.max_keep_default = max(1, int(max_keep_default))

    @staticmethod
    def _tail64_from_hash_hex(hash_hex: str) -> int:
        try:
            h = bytes.fromhex(hash_hex)
            if len(h) < 32:
                return 0xFFFFFFFFFFFFFFFF
            return int.from_bytes(h[24:32], "little", signed=False)
        except Exception:
            return 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def _share_diff_est(tail64: int) -> float:
        if tail64 <= 0:
            return float("inf")
        return float((1 << 64) / tail64)

    def rank(self, candidates: list[dict], max_results: int) -> list[dict]:
        keep = max(1, int(max_results or self.max_keep_default))

        seen: set[tuple[int, str]] = set()
        ranked: list[dict] = []

        for item in candidates:
            nonce_u32 = int(item.get("nonce_u32", 0)) & 0xFFFFFFFF
            hash_hex = str(item.get("hash_hex", ""))

            key = (nonce_u32, hash_hex)
            if key in seen:
                continue
            seen.add(key)

            tail64 = int(item.get("tail64", self._tail64_from_hash_hex(hash_hex))) & 0xFFFFFFFFFFFFFFFF
            share_diff_est = float(item.get("share_diff_est", self._share_diff_est(tail64)))

            ranked.append(
                {
                    "nonce_u32": nonce_u32,
                    "hash_hex": hash_hex,
                    "tail64": tail64,
                    "share_diff_est": share_diff_est,
                }
            )

        ranked.sort(
            key=lambda x: (
                int(x["tail64"]),
                -float(x["share_diff_est"]),
                int(x["nonce_u32"]),
            )
        )
        return ranked[:keep]


@dataclass
class _ExecutionLane:
    worker_index: int
    mode: str = "direct"  # "direct" | "usage" | "thunk"
    thunk: Any = None

    failures: int = 0
    access_violations: int = 0

    bind_attempts: int = 0
    invoke_attempts: int = 0

    direct_successes: int = 0
    native_successes: int = 0
    pressure_bypasses: int = 0

    last_error: Optional[str] = None
    last_ok: bool = False

    last_mode_change_at: float = 0.0
    last_native_try_at: float = 0.0
    next_retry_at: float = 0.0


class _HybridExecutionController:
    """
    Ultra-safe controller for heavy-thread RandomX mining.

    Policy:
    - direct hashing is always the primary path
    - native helpers are treated as fragile under high concurrency
    - when thread count / active work is high, NEVER attempt thunk/python_usage
    - native helpers are only eligible in low-pressure conditions
    """

    def __init__(
        self,
        *,
        threads: int,
        logger: Optional[Callable[[str], None]],
        jit: Optional["PythonJIT"],
        python_usage: Optional["PythonUsage"],
    ) -> None:
        self.threads = max(1, int(threads))
        self.logger = logger or (lambda s: None)
        self.jit = jit
        self.python_usage = python_usage

        self._mu = threading.RLock()
        self._usage_lock = threading.Lock()

        self._lanes: dict[int, _ExecutionLane] = {}
        self._usage_owner: Optional[int] = None
        self._thunk_lane_count = 0

        self._active_invocations = 0
        self._active_native_invocations = 0

        self._started_at = time.perf_counter()
        self._native_startup_grace_until = self._started_at + 8.0

        # Hard safety gates.
        # With many mining threads, do not attempt native helper paths at all.
        self._native_thread_cap_for_usage = 4
        self._native_thread_cap_for_thunk = 2

        self._usage_enabled = self.python_usage is not None
        self._thunk_enabled = self.jit is not None

        self._usage_permanently_disabled = False
        self._thunk_permanently_disabled = False

        self._usage_disabled_until = 0.0
        self._thunk_disabled_until = 0.0

        self._usage_av_count = 0
        self._thunk_av_count = 0

        self._stats = {
            "thunk_bind_ok": 0,
            "thunk_bind_fail": 0,
            "thunk_invoke_ok": 0,
            "thunk_invoke_fail": 0,
            "usage_bind_ok": 0,
            "usage_bind_fail": 0,
            "usage_invoke_ok": 0,
            "usage_invoke_fail": 0,
            "direct_invoke_ok": 0,
            "direct_invoke_fail": 0,
            "fallback_to_direct": 0,
            "promotion_attempts": 0,
            "promotion_ok": 0,
            "pressure_bypass_thunk": 0,
            "pressure_bypass_usage": 0,
            "native_disabled_by_thread_cap": 0,
            "access_violation_bind_thunk": 0,
            "access_violation_bind_usage": 0,
            "access_violation_invoke_thunk": 0,
            "access_violation_invoke_usage": 0,
        }

    def _log(self, msg: str) -> None:
        try:
            self.logger(msg)
        except Exception:
            pass

    @staticmethod
    def _now() -> float:
        return time.perf_counter()

    @staticmethod
    def _err_text(e: BaseException) -> str:
        return f"{type(e).__name__}: {e}"

    @staticmethod
    def _looks_like_access_violation_text(msg: str) -> bool:
        m = str(msg).lower()
        return (
            "access violation" in m
            or "0xc0000005" in m
            or "exception reading 0x0000000000000000" in m
            or "raised structured exception" in m
        )

    def _looks_like_access_violation_exc(self, e: BaseException) -> bool:
        return self._looks_like_access_violation_text(self._err_text(e))

    @staticmethod
    def _cooldown_seconds(
        failures: int,
        *,
        base: float = 2.0,
        cap: float = 120.0,
    ) -> float:
        failures = max(1, int(failures))
        return min(cap, base * (2.0 ** min(failures - 1, 5)))

    @staticmethod
    def _av_cooldown_seconds(
        av_count: int,
        *,
        base: float = 30.0,
        cap: float = 600.0,
    ) -> float:
        av_count = max(1, int(av_count))
        return min(cap, base * (2.0 ** min(av_count - 1, 4)))

    def _native_globally_safe(self) -> bool:
        # Core rule: never attempt native helpers at high thread counts.
        return self.threads <= self._native_thread_cap_for_usage

    def _feature_available_locked(self, feature: str) -> bool:
        now = self._now()

        if now < self._native_startup_grace_until:
            return False

        if self._active_invocations > 1:
            return False

        if self._active_native_invocations > 0:
            return False

        if feature == "usage":
            if not self._usage_enabled or self._usage_permanently_disabled:
                return False
            if now < self._usage_disabled_until:
                return False
            if self.python_usage is None:
                return False
            if self.threads > self._native_thread_cap_for_usage:
                return False
            return True

        if feature == "thunk":
            if not self._thunk_enabled or self._thunk_permanently_disabled:
                return False
            if now < self._thunk_disabled_until:
                return False
            if self.jit is None:
                return False
            if self.threads > self._native_thread_cap_for_thunk:
                return False
            return True

        return False

    def _eligible_for_usage_worker(self, worker_index: int) -> bool:
        return int(worker_index) == 0

    def _eligible_for_thunk_worker(self, worker_index: int) -> bool:
        return int(worker_index) == 0

    def _required_direct_successes_for_usage(self) -> int:
        return 32

    def _required_direct_successes_for_thunk(self) -> int:
        return 64

    def _release_thunk_locked(self, lane: _ExecutionLane) -> None:
        thunk = lane.thunk
        lane.thunk = None

        if thunk is not None and self.jit is not None:
            try:
                self.jit.destroy(thunk)
            except Exception:
                pass

        if self._thunk_lane_count > 0:
            self._thunk_lane_count -= 1

    def _record_access_violation_locked(
        self,
        lane: _ExecutionLane,
        *,
        feature: str,
        stage: str,
        reason: str,
    ) -> None:
        lane.access_violations += 1
        lane.last_error = reason
        lane.last_ok = False

        if feature == "usage":
            self._usage_av_count += 1
            self._usage_disabled_until = max(
                self._usage_disabled_until,
                self._now() + self._av_cooldown_seconds(self._usage_av_count),
            )
            if stage == "bind":
                self._stats["access_violation_bind_usage"] += 1
            else:
                self._stats["access_violation_invoke_usage"] += 1

            # One AV is enough to stop retrying for this session under mining load.
            self._usage_permanently_disabled = True
            self._log("[JITWorker] python_usage permanently disabled for this session after access violation")

        elif feature == "thunk":
            self._thunk_av_count += 1
            self._thunk_disabled_until = max(
                self._thunk_disabled_until,
                self._now() + self._av_cooldown_seconds(self._thunk_av_count),
            )
            if stage == "bind":
                self._stats["access_violation_bind_thunk"] += 1
            else:
                self._stats["access_violation_invoke_thunk"] += 1

            self._thunk_permanently_disabled = True
            self._log("[JITWorker] thunk permanently disabled for this session after access violation")

        lane.next_retry_at = max(
            lane.next_retry_at,
            self._now() + self._av_cooldown_seconds(lane.access_violations),
        )

    def _demote_to_direct_locked(
        self,
        lane: _ExecutionLane,
        *,
        reason: str,
        cooldown: float,
        clear_usage_owner: bool,
    ) -> None:
        if lane.mode == "thunk":
            self._release_thunk_locked(lane)

        if clear_usage_owner and self._usage_owner == lane.worker_index:
            self._usage_owner = None

        lane.mode = "direct"
        lane.failures += 1
        lane.last_ok = False
        lane.last_error = reason
        lane.last_mode_change_at = self._now()
        lane.next_retry_at = max(lane.next_retry_at, self._now() + max(1.0, float(cooldown)))

        self._stats["fallback_to_direct"] += 1

    def _invoke_python_usage_callable(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> int:
        if self.python_usage is None:
            raise RuntimeError("python_usage unavailable")

        with self._usage_lock:
            self.python_usage.set_function(func, *args, **kwargs)
            rc = int(self.python_usage.run_once())

            get_err = getattr(self.python_usage, "get_last_error", None)
            if callable(get_err):
                err = get_err()
                if err is not None:
                    raise err

            return rc

    def _should_attempt_usage_locked(self, lane: _ExecutionLane) -> bool:
        if not self._feature_available_locked("usage"):
            if self.threads > self._native_thread_cap_for_usage:
                self._stats["native_disabled_by_thread_cap"] += 1
            return False
        if self._usage_owner is not None:
            return False
        if not self._eligible_for_usage_worker(lane.worker_index):
            return False
        if self._now() < lane.next_retry_at:
            return False
        if lane.direct_successes < self._required_direct_successes_for_usage():
            return False
        if (self._now() - lane.last_native_try_at) < 2.0:
            return False
        return True

    def _should_attempt_thunk_locked(self, lane: _ExecutionLane) -> bool:
        if not self._feature_available_locked("thunk"):
            if self.threads > self._native_thread_cap_for_thunk:
                self._stats["native_disabled_by_thread_cap"] += 1
            return False
        if self._thunk_lane_count >= self._max_thunk_lanes:
            return False
        if not self._eligible_for_thunk_worker(lane.worker_index):
            return False
        if self._now() < lane.next_retry_at:
            return False
        if lane.direct_successes < self._required_direct_successes_for_thunk():
            return False
        if (self._now() - lane.last_native_try_at) < 4.0:
            return False
        return True

    def _maybe_promote_locked(self, st: "_ThreadState", lane: _ExecutionLane) -> None:
        if lane.mode != "direct":
            return

        if self._should_attempt_usage_locked(lane):
            self._stats["promotion_attempts"] += 1
            lane.bind_attempts += 1
            lane.last_native_try_at = self._now()
            try:
                self._usage_owner = int(st.worker_index)
                lane.mode = "usage"
                lane.thunk = None
                lane.last_error = None
                lane.last_ok = True
                lane.last_mode_change_at = self._now()
                self._stats["usage_bind_ok"] += 1
                self._stats["promotion_ok"] += 1
                self._log(f"[JITWorker] worker[{st.worker_index}] execution=python_usage")
                return
            except Exception as e:
                msg = self._err_text(e)
                lane.last_error = msg
                if self._looks_like_access_violation_exc(e):
                    self._record_access_violation_locked(
                        lane,
                        feature="usage",
                        stage="bind",
                        reason=msg,
                    )
                else:
                    lane.next_retry_at = self._now() + self._cooldown_seconds(lane.failures + 1, base=3.0)
                self._stats["usage_bind_fail"] += 1

        if self._should_attempt_thunk_locked(lane):
            self._stats["promotion_attempts"] += 1
            lane.bind_attempts += 1
            lane.last_native_try_at = self._now()
            try:
                thunk = self.jit.create_int_thunk0(st.callback, None)
                lane.mode = "thunk"
                lane.thunk = thunk
                lane.last_error = None
                lane.last_ok = True
                lane.last_mode_change_at = self._now()
                self._thunk_lane_count += 1
                self._stats["thunk_bind_ok"] += 1
                self._stats["promotion_ok"] += 1
                self._log(f"[JITWorker] worker[{st.worker_index}] execution=thunk")
                return
            except Exception as e:
                msg = self._err_text(e)
                lane.last_error = msg
                if self._looks_like_access_violation_exc(e):
                    self._record_access_violation_locked(
                        lane,
                        feature="thunk",
                        stage="bind",
                        reason=msg,
                    )
                else:
                    lane.next_retry_at = self._now() + self._cooldown_seconds(lane.failures + 1, base=3.0)
                self._stats["thunk_bind_fail"] += 1

    def bind_worker(self, st: "_ThreadState") -> str:
        lane = _ExecutionLane(
            worker_index=int(st.worker_index),
            mode="direct",
            last_mode_change_at=self._now(),
        )

        with self._mu:
            self._lanes[int(st.worker_index)] = lane

        st.thunk = None
        return "direct"

    def invoke(self, st: "_ThreadState") -> int:
        idx = int(st.worker_index)

        with self._mu:
            lane = self._lanes.get(idx)
            if lane is None:
                lane = _ExecutionLane(
                    worker_index=idx,
                    mode="direct",
                    last_mode_change_at=self._now(),
                )
                self._lanes[idx] = lane

            self._active_invocations += 1
            lane.invoke_attempts += 1

        try:
            # Under mining load, direct work always happens.
            rc = int(st.callback(None))

            with self._mu:
                lane.last_ok = True
                lane.last_error = None
                lane.direct_successes += 1
                self._stats["direct_invoke_ok"] += 1

            # Only after direct work succeeds do we optionally sample native.
            with self._mu:
                if lane.mode == "direct":
                    self._maybe_promote_locked(st, lane)

            if lane.mode == "usage" and self.python_usage is not None:
                with self._mu:
                    can_try_usage = self._feature_available_locked("usage") and self._usage_owner == lane.worker_index
                    if can_try_usage:
                        self._active_native_invocations += 1
                    else:
                        lane.pressure_bypasses += 1
                        self._stats["pressure_bypass_usage"] += 1

                if can_try_usage:
                    try:
                        native_rc = self._invoke_python_usage_callable(st.callback, None)
                        with self._mu:
                            lane.native_successes += 1
                            lane.last_native_try_at = self._now()
                            lane.last_ok = True
                            lane.last_error = None
                            self._stats["usage_invoke_ok"] += 1
                        rc = int(native_rc)
                    except Exception as e:
                        msg = self._err_text(e)
                        with self._mu:
                            self._stats["usage_invoke_fail"] += 1
                            if self._looks_like_access_violation_exc(e):
                                self._record_access_violation_locked(
                                    lane,
                                    feature="usage",
                                    stage="invoke",
                                    reason=msg,
                                )
                            self._demote_to_direct_locked(
                                lane,
                                reason=msg,
                                cooldown=self._cooldown_seconds(lane.failures + 1, base=4.0),
                                clear_usage_owner=True,
                            )
                    finally:
                        with self._mu:
                            if self._active_native_invocations > 0:
                                self._active_native_invocations -= 1

            elif lane.mode == "thunk" and lane.thunk is not None and self.jit is not None:
                with self._mu:
                    can_try_thunk = self._feature_available_locked("thunk")
                    if can_try_thunk:
                        self._active_native_invocations += 1
                    else:
                        lane.pressure_bypasses += 1
                        self._stats["pressure_bypass_thunk"] += 1

                if can_try_thunk:
                    try:
                        native_rc = int(self.jit.invoke_int0(lane.thunk))
                        with self._mu:
                            lane.native_successes += 1
                            lane.last_native_try_at = self._now()
                            lane.last_ok = True
                            lane.last_error = None
                            self._stats["thunk_invoke_ok"] += 1
                        rc = native_rc
                    except Exception as e:
                        msg = self._err_text(e)
                        with self._mu:
                            self._stats["thunk_invoke_fail"] += 1
                            if self._looks_like_access_violation_exc(e):
                                self._record_access_violation_locked(
                                    lane,
                                    feature="thunk",
                                    stage="invoke",
                                    reason=msg,
                                )
                            self._demote_to_direct_locked(
                                lane,
                                reason=msg,
                                cooldown=self._cooldown_seconds(lane.failures + 1, base=4.0),
                                clear_usage_owner=False,
                            )
                    finally:
                        with self._mu:
                            if self._active_native_invocations > 0:
                                self._active_native_invocations -= 1

            return rc

        except Exception as e:
            with self._mu:
                lane.last_ok = False
                lane.last_error = self._err_text(e)
                self._stats["direct_invoke_fail"] += 1
            raise

        finally:
            with self._mu:
                if self._active_invocations > 0:
                    self._active_invocations -= 1

    def close(self) -> None:
        with self._mu:
            for lane in self._lanes.values():
                if lane.thunk is not None and self.jit is not None:
                    try:
                        self.jit.destroy(lane.thunk)
                    except Exception:
                        pass
                    lane.thunk = None

            self._lanes.clear()
            self._usage_owner = None
            self._thunk_lane_count = 0
            self._active_invocations = 0
            self._active_native_invocations = 0

    def snapshot(self) -> dict:
        with self._mu:
            return {
                "threads": self.threads,
                "usage_enabled": self._usage_enabled,
                "thunk_enabled": self._thunk_enabled,
                "usage_permanently_disabled": self._usage_permanently_disabled,
                "thunk_permanently_disabled": self._thunk_permanently_disabled,
                "usage_disabled_until": self._usage_disabled_until,
                "thunk_disabled_until": self._thunk_disabled_until,
                "usage_av_count": self._usage_av_count,
                "thunk_av_count": self._thunk_av_count,
                "usage_owner": self._usage_owner,
                "native_startup_grace_until": self._native_startup_grace_until,
                "active_invocations": self._active_invocations,
                "active_native_invocations": self._active_native_invocations,
                "stats": dict(self._stats),
                "lanes": {
                    idx: {
                        "mode": lane.mode,
                        "failures": lane.failures,
                        "access_violations": lane.access_violations,
                        "bind_attempts": lane.bind_attempts,
                        "invoke_attempts": lane.invoke_attempts,
                        "direct_successes": lane.direct_successes,
                        "native_successes": lane.native_successes,
                        "pressure_bypasses": lane.pressure_bypasses,
                        "last_error": lane.last_error,
                        "last_ok": lane.last_ok,
                        "has_thunk": bool(lane.thunk),
                        "last_mode_change_at": lane.last_mode_change_at,
                        "last_native_try_at": lane.last_native_try_at,
                        "next_retry_at": lane.next_retry_at,
                    }
                    for idx, lane in self._lanes.items()
                },
            }

class RandomXDatasetBuilder:
    """
    Centralizes RandomX seed changes so only one thread pays the full
    dataset/cache rebuild cost per seed.

    It does not change the external RandomX wrapper API. It just coordinates
    calls into rx.ensure_seed(seed_hash).
    """

    def __init__(
        self,
        *,
        randomx: "RandomX",
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.rx = randomx
        self.logger = logger or (lambda s: None)

        self._mu = threading.RLock()
        self._cv = threading.Condition(self._mu)

        self._ready_seed: bytes = b""
        self._ready_epoch: int = 0
        self._building_seed: Optional[bytes] = None
        self._build_error: Optional[BaseException] = None

        self._stats = {
            "build_requests": 0,
            "build_starts": 0,
            "build_waits": 0,
            "build_success": 0,
            "build_fail": 0,
        }

    def _log(self, msg: str) -> None:
        try:
            self.logger(msg)
        except Exception:
            pass

    def ensure_seed_ready(self, seed_hash: bytes) -> int:
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        with self._cv:
            self._stats["build_requests"] += 1

            while True:
                if self._ready_seed == seed_hash and self._build_error is None:
                    return self._ready_epoch

                if self._building_seed == seed_hash:
                    self._stats["build_waits"] += 1
                    self._cv.wait()
                    continue

                if self._building_seed is None:
                    self._building_seed = seed_hash
                    self._build_error = None
                    self._stats["build_starts"] += 1
                    break

                self._stats["build_waits"] += 1
                self._cv.wait()

        try:
            self.rx.ensure_seed(seed_hash)
        except BaseException as e:
            with self._cv:
                self._building_seed = None
                self._build_error = e
                self._stats["build_fail"] += 1
                self._cv.notify_all()
            raise

        with self._cv:
            self._ready_seed = seed_hash
            self._ready_epoch += 1
            self._building_seed = None
            self._build_error = None
            self._stats["build_success"] += 1
            epoch = self._ready_epoch
            self._cv.notify_all()
            return epoch

    def current_seed(self) -> bytes:
        with self._mu:
            return self._ready_seed

    def current_epoch(self) -> int:
        with self._mu:
            return self._ready_epoch

    def snapshot(self) -> dict:
        with self._mu:
            return {
                "ready_seed_hex": self._ready_seed.hex() if self._ready_seed else "",
                "ready_epoch": self._ready_epoch,
                "building_seed_hex": self._building_seed.hex() if self._building_seed else "",
                "has_build_error": self._build_error is not None,
                "stats": dict(self._stats),
            }


class RandomXVmPool:
    """
    Keeps one VM per worker and recreates it only when the RandomX dataset epoch
    changes. This keeps VM lifecycle stable and moves seed coordination out of
    the hot loop.
    """

    def __init__(
        self,
        *,
        randomx: "RandomX",
        dataset_builder: RandomXDatasetBuilder,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.rx = randomx
        self.dataset_builder = dataset_builder
        self.logger = logger or (lambda s: None)

        self._mu = threading.RLock()
        self._entries: dict[int, dict[str, Any]] = {}
        self._stats = {
            "acquire_calls": 0,
            "vm_creates": 0,
            "vm_reuses": 0,
            "vm_rebuilds": 0,
            "vm_destroy": 0,
            "warm_calls": 0,
        }

    def _log(self, msg: str) -> None:
        try:
            self.logger(msg)
        except Exception:
            pass

    def _destroy_entry_vm_locked(self, entry: dict[str, Any]) -> None:
        vm = entry.get("vm")
        if vm is not None:
            try:
                self.rx.destroy_vm(vm)
            except Exception:
                pass
            entry["vm"] = None
            self._stats["vm_destroy"] += 1

    def acquire_for_worker(self, worker_index: int, seed_hash: bytes) -> tuple[Any, int]:
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        epoch = self.dataset_builder.ensure_seed_ready(seed_hash)

        with self._mu:
            self._stats["acquire_calls"] += 1
            idx = int(worker_index)

            entry = self._entries.get(idx)
            if entry is None:
                vm = self.rx.create_vm()
                self._entries[idx] = {
                    "vm": vm,
                    "epoch": epoch,
                    "seed_hash": seed_hash,
                }
                self._stats["vm_creates"] += 1
                return vm, epoch

            if entry.get("vm") is not None and int(entry.get("epoch", 0)) == epoch:
                self._stats["vm_reuses"] += 1
                return entry["vm"], epoch

            self._destroy_entry_vm_locked(entry)
            vm = self.rx.create_vm()
            entry["vm"] = vm
            entry["epoch"] = epoch
            entry["seed_hash"] = seed_hash
            self._stats["vm_rebuilds"] += 1
            return vm, epoch

    def warm_workers(self, worker_indices: list[int], seed_hash: bytes) -> int:
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        epoch = self.dataset_builder.ensure_seed_ready(seed_hash)
        self._stats["warm_calls"] += 1

        for idx in worker_indices:
            self.acquire_for_worker(int(idx), seed_hash)

        return epoch

    def close(self) -> None:
        with self._mu:
            for entry in self._entries.values():
                self._destroy_entry_vm_locked(entry)
            self._entries.clear()

    def snapshot(self) -> dict:
        with self._mu:
            return {
                "pool_size": len(self._entries),
                "stats": dict(self._stats),
                "workers": {
                    int(idx): {
                        "has_vm": entry.get("vm") is not None,
                        "epoch": int(entry.get("epoch", 0)),
                        "seed_hash_hex": bytes(entry.get("seed_hash", b"")).hex(),
                    }
                    for idx, entry in self._entries.items()
                },
            }


@dataclass
class _ThreadState:
    worker_index: int
    vm: Any = None
    vm_epoch: int = 0
    blob_buf: Any = None
    nonce_ptr: Any = None
    out_buf: Any = None
    last_seed: bytes = b""
    last_blob: bytes = b""

    assigned_job: Optional["MoneroJob"] = None
    assigned_generation: int = 0
    assigned_start_nonce: int = 0
    assigned_count: int = 0
    assigned_max_results: int = 0

    done_hashes: int = 0
    found: list[dict] | None = None
    error: Optional[str] = None
    busy: bool = False

    start_event: threading.Event | None = None
    done_event: threading.Event | None = None
    stop_event: threading.Event | None = None

    thunk: Any = None
    callback: Any = None
    exec_mode: str = "direct"


class JITWorker:
    """
    Safe JITWorker:
    - keeps the same API used by miner_core.py
    - tries a very small number of thunk lanes
    - tries one serialized PythonUsage lane
    - falls back to direct callback execution when native helper paths fail
    - centralizes RandomX seed building and per-worker VM reuse

    No external changes required:
    - same constructor
    - same hash_job(...) signature
    - same stop()
    """

    def __init__(
        self,
        *,
        threads: int,
        logger: Optional[Callable[[str], None]],
        randomx: "RandomX",
        jit: "PythonJIT",
        batch_size: int = 1024,
        python_usage: "PythonUsage"
    ) -> None:
        self.threads = max(1, int(threads))
        self.logger = logger or (lambda s: None)
        self.rx = randomx
        self.jit = jit
        self.batch_size = max(1, int(batch_size))
        self.python_usage = python_usage

        self._stop = threading.Event()
        self._states: list[_ThreadState] = []
        self._threads: list[threading.Thread] = []
        self._mu = threading.RLock()

        self._dispatch = _JobDispatchCoordinator(hashed_job_start=True)
        self._selector = _CandidateSelector(max_keep_default=16)
        self._exec = _HybridExecutionController(
            threads=self.threads,
            logger=self.logger,
            jit=self.jit,
            python_usage=self.python_usage,
        )
        self._dataset_builder = RandomXDatasetBuilder(
            randomx=self.rx,
            logger=self.logger,
        )
        self._vm_pool = RandomXVmPool(
            randomx=self.rx,
            dataset_builder=self._dataset_builder,
            logger=self.logger,
        )

        self._bootstrap_workers()

    def _effective_count(self, requested_count: int) -> int:
        count = max(0, int(requested_count))
        if count <= 0:
            return 0

        age_ms = self._dispatch.current_job_age_ms()

        if age_ms <= 0.0:
            return count
        if age_ms < 150.0:
            return count
        if age_ms < 350.0:
            return min(count, max(256, self.batch_size))
        if age_ms < 800.0:
            return min(count, max(128, self.batch_size // 2))
        return min(count, 128)

    def _stale_check_mask(self) -> int:
        age_ms = self._dispatch.current_job_age_ms()
        if age_ms < 150.0:
            return 63
        if age_ms < 400.0:
            return 31
        if age_ms < 900.0:
            return 15
        return 7

    def _bootstrap_workers(self) -> None:
        jit_version = "unavailable"
        try:
            jit_version = str(self.jit.version())
        except Exception:
            pass

        for i in range(self.threads):
            st = _ThreadState(
                worker_index=i,
                out_buf=(c_ubyte * 32)(),
                found=[],
                start_event=threading.Event(),
                done_event=threading.Event(),
                stop_event=self._stop,
            )
            st.callback = self._make_callback(st)
            st.thunk = None
            st.exec_mode = self._exec.bind_worker(st)

            t = threading.Thread(
                target=self._thread_main,
                args=(st,),
                name=f"JITWorker-{i}",
                daemon=True,
            )
            self._states.append(st)
            self._threads.append(t)
            t.start()

        self.logger(
            f"[JITWorker] initialized: threads={self.threads} "
            f"batch_size={self.batch_size} jit_version={jit_version} "
            f"(hybrid mode: capped thunk lanes + single python_usage lane + vm pool)"
        )

    def _make_callback(self, st: _ThreadState):
        def _cb(_user_data=None) -> int:
            try:
                st.error = None
                st.done_hashes = 0
                if st.found is None:
                    st.found = []
                else:
                    st.found.clear()

                job = st.assigned_job
                if job is None:
                    return 0

                job_id = str(job.job_id)
                my_generation = int(st.assigned_generation or 0)
                if my_generation <= 0:
                    return 0

                if not self._dispatch.is_current(job_id, my_generation):
                    return 0

                self._ensure_thread_resources(st, job)

                rx_hash_into = self.rx.hash_into
                target64 = int(job.target64) & 0xFFFFFFFFFFFFFFFF

                keep_best = max(1, int(st.assigned_max_results))
                start_nonce = int(st.assigned_start_nonce) & 0xFFFFFFFF
                count = max(0, int(st.assigned_count))

                stop_flag = self._stop
                nonce_ptr = st.nonce_ptr
                blob_buf = st.blob_buf
                out_buf = st.out_buf
                is_current = self._dispatch.is_current
                stale_mask = self._stale_check_mask()

                done = 0
                local_heap: list[tuple[tuple[int, float, int], dict]] = []

                for i in range(count):
                    if stop_flag.is_set():
                        break

                    if (i & stale_mask) == 0 and not is_current(job_id, my_generation):
                        break

                    nonce_u32 = (start_nonce + i) & 0xFFFFFFFF
                    nonce_ptr[0] = nonce_u32
                    rx_hash_into(st.vm, blob_buf, out_buf)
                    done += 1

                    tail64 = int.from_bytes(bytes(out_buf[24:32]), "little", signed=False)

                    if tail64 < target64:
                        h32 = bytes(out_buf)
                        share_diff_est = float("inf") if tail64 == 0 else float((1 << 64) / tail64)

                        self._keep_local_best(
                            local_heap,
                            {
                                "nonce_u32": nonce_u32,
                                "hash_hex": h32.hex(),
                                "tail64": tail64,
                                "share_diff_est": share_diff_est,
                            },
                            keep_best,
                        )

                st.found = [
                    item
                    for _, item in sorted(local_heap, key=lambda x: self._candidate_sort_key(x[1]))
                ]

                st.done_hashes = done
                return done

            except Exception as e:
                st.error = f"{type(e).__name__}: {e}"
                return -1

        return _cb

    def _ensure_thread_resources(self, st: _ThreadState, job: "MoneroJob") -> None:
        seed_hash = bytes(job.seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        if st.vm is None or st.last_seed != seed_hash:
            vm, epoch = self._vm_pool.acquire_for_worker(st.worker_index, seed_hash)
            st.vm = vm
            st.vm_epoch = int(epoch)
            st.last_seed = seed_hash

        blob_changed = (st.last_blob != job.blob)

        if st.blob_buf is None or len(st.blob_buf) != len(job.blob):
            st.blob_buf = (c_ubyte * len(job.blob))()
            blob_changed = True

        if blob_changed:
            memmove(st.blob_buf, job.blob, len(job.blob))
            st.last_blob = bytes(job.blob)

        st.nonce_ptr = cast(
            byref(st.blob_buf, int(job.nonce_offset)),
            POINTER(c_uint32)
        )

    def _thread_main(self, st: _ThreadState) -> None:
        while True:
            st.start_event.wait()
            st.start_event.clear()

            if self._stop.is_set():
                break

            st.done_event.clear()
            st.busy = True
            try:
                self._exec.invoke(st)
            except Exception as e:
                st.error = f"{type(e).__name__}: {e}"
            finally:
                st.busy = False
                st.done_event.set()

    def hash_job(
        self,
        *,
        job: "MoneroJob",
        start_nonce: int,
        count: int,
        max_results: int,
    ) -> dict:
        count = self._effective_count(count)
        if count <= 0:
            return {
                "job_id": job.job_id,
                "hashes_done": 0,
                "found": [],
                "elapsed_sec": 0.0,
                "errors": [],
            }

        actual_start_nonce, generation = self._dispatch.observe_and_reserve(
            job.job_id,
            start_nonce,
            count,
        )

        try:
            setattr(job, "generation", int(generation))
        except Exception:
            pass

        t0 = time.perf_counter()

        # Eagerly ensure the seed is ready once per job dispatch and warm the VMs
        # for the workers that will actually participate in this batch.
        try:
            threads = min(self.threads, count)
            active_indices = list(range(threads))
            self._vm_pool.warm_workers(active_indices, bytes(job.seed_hash or b""))
        except Exception as e:
            return {
                "job_id": job.job_id,
                "hashes_done": 0,
                "found": [],
                "elapsed_sec": max(0.0, time.perf_counter() - t0),
                "errors": [f"randomx_prepare {type(e).__name__}: {e}"],
            }

        per_thread = count // threads
        remainder = count % threads

        cursor = int(actual_start_nonce) & 0xFFFFFFFF
        active_states: list[_ThreadState] = []

        per_thread_candidate_budget = max(
            4,
            min(256, max(1, int(max_results)) * 8),
        )

        for i in range(threads):
            take = per_thread + (1 if i < remainder else 0)
            if take <= 0:
                continue

            st = self._states[i]
            st.assigned_job = job
            st.assigned_generation = generation
            st.assigned_start_nonce = cursor
            st.assigned_count = take
            st.assigned_max_results = per_thread_candidate_budget
            st.done_hashes = 0

            if st.found is None:
                st.found = []
            else:
                st.found.clear()

            st.error = None
            st.done_event.clear()

            cursor = (cursor + take) & 0xFFFFFFFF
            active_states.append(st)

        for st in active_states:
            st.start_event.set()

        for st in active_states:
            st.done_event.wait()

        hashes_done = 0
        gathered: list[dict] = []
        errors: list[str] = []

        for st in active_states:
            hashes_done += int(st.done_hashes or 0)
            if st.found:
                gathered.extend(st.found)
            if st.error:
                errors.append(f"worker[{st.worker_index}] {st.error}")

        found = self._selector.rank(gathered, max_results=max_results)

        return {
            "job_id": job.job_id,
            "hashes_done": hashes_done,
            "found": found,
            "elapsed_sec": max(0.0, time.perf_counter() - t0),
            "errors": errors,
        }

    def snapshot_execution(self) -> dict:
        return self._exec.snapshot()

    def snapshot_randomx(self) -> dict:
        return {
            "dataset_builder": self._dataset_builder.snapshot(),
            "vm_pool": self._vm_pool.snapshot(),
        }

    @staticmethod
    def _candidate_sort_key(item: dict) -> tuple[int, float, int]:
        return (
            int(item["tail64"]),
            -float(item["share_diff_est"]),
            int(item["nonce_u32"]),
        )

    @staticmethod
    def _candidate_heap_key(item: dict) -> tuple[int, float, int]:
        # heap root should be the WORST kept candidate
        # worse = larger tail64, lower diff, larger nonce
        return (
            -int(item["tail64"]),
            float(item["share_diff_est"]),
            -int(item["nonce_u32"]),
        )

    def _keep_local_best(self, heap: list[tuple[tuple[int, float, int], dict]], item: dict, keep: int) -> None:
        keep = max(1, int(keep))
        entry = (self._candidate_heap_key(item), item)

        if len(heap) < keep:
            heapq.heappush(heap, entry)
            return

        # If the new candidate is better than the current worst kept one, replace it.
        if entry[0] > heap[0][0]:
            heapq.heapreplace(heap, entry)

    def stop(self) -> None:
        self._stop.set()

        for st in self._states:
            try:
                st.start_event.set()
            except Exception:
                pass

        for t in self._threads:
            try:
                t.join(timeout=1.0)
            except Exception:
                pass

        try:
            self._exec.close()
        except Exception:
            pass

        try:
            self._vm_pool.close()
        except Exception:
            pass

        for st in self._states:
            st.vm = None
            st.vm_epoch = 0