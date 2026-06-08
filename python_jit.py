from __future__ import annotations

import ctypes
import hashlib
import os
import random
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
from typing import Callable, Optional, Any, Dict, Tuple

from monero_job import MoneroJob
from python_usage import PythonUsage
from randomx_ctypes import RandomX
import sys
import heapq
from monero_hot_hash import (
    MoneroHashLoopDLL,
    MoneroHotHashError,
    HH_CANDIDATE_OVERFLOW,
)
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

class _ClassEventLogMixin:
    """
    Shared sparse natural-event logger for runtime classes.
    """

    def _evt_init(
        self,
        *,
        class_prefix: str,
        logger: Optional[Callable[[str], None]],
        cooldowns: Optional[dict[str, float]] = None,
        phrases: Optional[dict[str, list[str]]] = None,
    ) -> None:
        self.logger = logger or (lambda s: None)
        self._evt_prefix = str(class_prefix)
        self._evt_last_at: dict[str, float] = {}
        self._evt_last_phrase: dict[str, str] = {}
        self._evt_rng = random.Random(
            int(time.time() * 1_000_000) ^ id(self) ^ hash(self._evt_prefix)
        )
        self._evt_cooldowns = dict(cooldowns or {})
        self._evt_phrases = dict(phrases or {})

    def _evt_write(self, text: str) -> None:
        try:
            self.logger(text)
        except Exception:
            pass

    def _evt_allowed(self, key: str, cooldown: Optional[float] = None) -> bool:
        now = time.perf_counter()
        cd = float(
            self._evt_cooldowns.get(
                key,
                45.0 if cooldown is None else cooldown,
            )
        )
        last = float(self._evt_last_at.get(key, 0.0))
        if (now - last) < cd:
            return False
        self._evt_last_at[key] = now
        return True

    def _evt_pick(self, key: str, phrases: Optional[list[str]] = None) -> str:
        pool = list(phrases or self._evt_phrases.get(key, []))
        if not pool:
            return key

        last = self._evt_last_phrase.get(key, "")
        if len(pool) > 1 and last in pool:
            pool = [p for p in pool if p != last]

        picked = self._evt_rng.choice(pool)
        self._evt_last_phrase[key] = picked
        return picked

    def _evt_emit(
        self,
        key: str,
        *,
        details: str = "",
        phrases: Optional[list[str]] = None,
        cooldown: Optional[float] = None,
        force: bool = False,
    ) -> None:
        if not force and not self._evt_allowed(key, cooldown):
            return

        phrase = self._evt_pick(key, phrases)
        if details:
            self._evt_write(f"[{self._evt_prefix}] {phrase} | {details}")
        else:
            self._evt_write(f"[{self._evt_prefix}] {phrase}")

class _RxHashAdvanceLane(_ClassEventLogMixin):
    """
    Advanced worker-local RandomX lane.
    Optimized for maximum HPS (Hashes Per Second) and reduced Python overhead.
    """

    BEGIN_LOG_EVERY_N_ROUNDS = 6
    BEGIN_LOG_MIN_EXPECTED_HASHES = 128
    BEGIN_LOG_FORCE_EXPECTED_HASHES = 4096

    FINISH_LOG_MIN_HASHES = 262144
    HIT_LOG_MIN_IMPROVEMENT_RATIO = 0.95

    __slots__ = (
        "worker_index", "owner_key", "_hash_into", "_vm", "_blob_buf", "_out_buf",
        "_job_id", "_generation", "_target64", "_expected_hashes", "_hashes",
        "_hits", "_failures", "_consecutive_failures", "_best_tail64", "_best_nonce_u32",
        "_last_error", "_opened_at", "_active", "_summary_enabled", "_warmed",
        "_last_logged_job", "_last_logged_generation", "_last_logged_bucket",
        "_seen_any_begin", "_logged_begin_for_current_round", "_last_hit_logged_tail64",
    )

    # Class-level static data for threading safety
    _GLOBAL_EVT_MU = threading.RLock()
    _GLOBAL_SCOPE_NEXT_AT: Dict[Tuple, float] = {}
    _GLOBAL_SCOPE_SUPPRESSED: Dict[Tuple, int] = {}

    def __init__(
        self,
        *,
        worker_index: Optional[int] = None,
        owner_key: Optional[str] = None,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        # Use fast int conversion to avoid overhead
        self.worker_index = None if worker_index is None else int(worker_index)
        self.owner_key = (
            str(owner_key)
            if owner_key is not None
            else (f"worker-{self.worker_index}" if self.worker_index is not None else "rx-advance")
        )

        # Initialize buffers early to avoid None checks
        self._hash_into = None
        self._vm = None
        self._blob_buf = None
        self._out_buf = None

        # State vars
        self._job_id = ""
        self._generation = 0
        self._target64 = 0xFFFFFFFFFFFFFFFF
        self._expected_hashes = 0

        self._hashes = 0
        self._hits = 0
        self._failures = 0
        self._consecutive_failures = 0
        self._best_tail64 = 0xFFFFFFFFFFFFFFFF
        self._best_nonce_u32 = -1
        self._last_error = ""
        self._opened_at = 0.0
        self._active = False
        self._summary_enabled = False
        self._warmed = False

        # Logging state
        self._last_logged_job = ""
        self._last_logged_generation = 0
        self._last_logged_bucket = -1
        self._seen_any_begin = False
        self._logged_begin_for_current_round = False
        self._last_hit_logged_tail64 = 0xFFFFFFFFFFFFFFFF

        # Setup event system with minimal overhead
        self._evt_init(
            class_prefix="RxHashAdvance",
            logger=logger,
            cooldowns={
                "begin": 30.0, "warmup": 40.0, "progress": 60.0, "hit": 30.0,
                "error": 60.0, "finish": 30.0, "clear": 60.0,
            },
            phrases={
                "begin": ["the advanced rx lane aligned", "a smarter hashing lane locked on"],
                "warmup": ["the rx lane warmed clean", "the hashing lane primed success"],
                "progress": ["the rx lane chewed steadily", "the hashing lane built distance"],
                "hit": ["the lane surfaced a clean hit", "a sharper tail64 rose"],
                "error": ["the advanced rx lane caught a fault", "the hashing lane tripped"],
                "finish": ["the advanced rx lane wrapped a slice", "the hashing lane closed out"],
                "clear": ["the advanced rx lane cooled back", "the hashing lane stepped down"],
            },
        )

    @staticmethod
    def _u32(v: int) -> int:
        return int(v) & 0xFFFFFFFF

    @staticmethod
    def _u64(v: int) -> int:
        return int(v) & 0xFFFFFFFFFFFFFFFF

    # --- OPTIMIZED: Fast tail64 extraction ---
    # Removed redundant int() casts as bytearray/bytes indexing returns int directly
    @staticmethod
    def _tail64_fast(out_buf) -> int:
        # Ensure out_buf is buffer-like. If bytes/bytearray, indexing is fast.
        # Optimization: Direct integer arithmetic on extracted bytes
        return (
            out_buf[24] |
            (out_buf[25] << 8) |
            (out_buf[26] << 16) |
            (out_buf[27] << 24) |
            (out_buf[28] << 32) |
            (out_buf[29] << 40) |
            (out_buf[30] << 48) |
            (out_buf[31] << 56)
        )

    @staticmethod
    def _count_bucket(count: int) -> int:
        count = max(0, int(count))
        if count == 0: return 0
        # Simplified thresholding for fast branch prediction
        if count <= 0: return 0
        if count <= 8: return 8
        if count <= 16: return 16
        if count <= 32: return 32
        if count <= 64: return 64
        if count <= 128: return 128
        if count <= 256: return 256
        if count <= 512: return 512
        if count <= 1024: return 1024
        if count <= 4096: return 4096
        return 16384

    # --- OPTIMIZED: Scoped Event Emission (Locks & Dictionaries) ---
    def _scoped_evt_emit(
        self,
        key: str,
        *,
        scope_key: tuple,
        details: str = "",
        cooldown: Optional[float] = None,
        force: bool = False,
        phrases: Optional[list[str]] = None,
    ) -> bool:
        now = time.perf_counter()
        cd = float(self._evt_cooldowns.get(key, 45.0 if cooldown is None else cooldown))

        # Local scope dict lookups to minimize global access overhead
        suppressed = 0
        with self._GLOBAL_EVT_MU:
            next_at = float(self._GLOBAL_SCOPE_NEXT_AT.get(scope_key, 0.0))
            if not force and now < next_at:
                curr_suppressed = self._GLOBAL_SCOPE_SUPPRESSED.get(scope_key, 0)
                self._GLOBAL_SCOPE_SUPPRESSED[scope_key] = curr_suppressed + 1
                return False

            suppressed = int(self._GLOBAL_SCOPE_SUPPRESSED.pop(scope_key, 0))
            self._GLOBAL_SCOPE_NEXT_AT[scope_key] = now + cd

        phrase = self._evt_pick(key, phrases)
        extra = f" suppressed={suppressed}" if suppressed > 0 else ""
        if details:
            self._evt_write(f"[{self._evt_prefix}] {phrase} | {details}{extra}")
        else:
            self._evt_write(f"[{self._evt_prefix}] {phrase}{extra}")
        return True

    def _job_evt_emit(self, key: str, *, details: str = "", cooldown: Optional[float] = None, force: bool = False, phrases: Optional[list[str]] = None) -> bool:
        # Hoisted tuple creation slightly for speed, kept logic identical
        return self._scoped_evt_emit(
            key,
            scope_key=(self._evt_prefix, "job", key, self._job_id, int(self._generation)),
            details=details, cooldown=cooldown, force=force, phrases=phrases,
        )

    def _owner_evt_emit(self, key: str, *, details: str = "", cooldown: Optional[float] = None, force: bool = False, phrases: Optional[list[str]] = None) -> bool:
        return self._scoped_evt_emit(
            key,
            scope_key=(self._evt_prefix, "owner", key, self.owner_key),
            details=details, cooldown=cooldown, force=force, phrases=phrases,
        )

    def _class_evt_emit(self, key: str, *, details: str = "", cooldown: Optional[float] = None, force: bool = False, phrases: Optional[list[str]] = None) -> bool:
        return self._scoped_evt_emit(
            key,
            scope_key=(self._evt_prefix, "class", key),
            details=details, cooldown=cooldown, force=force, phrases=phrases,
        )

    def _should_sample_begin_round(
        self,
        *,
        job_id: str,
        generation: int,
        expected_hashes: int,
        force_log: bool,
    ) -> bool:
        if force_log: return True
        expected_hashes = max(0, int(expected_hashes))
        if expected_hashes < self.BEGIN_LOG_MIN_EXPECTED_HASHES: return False
        if expected_hashes >= self.BEGIN_LOG_FORCE_EXPECTED_HASHES: return True
        raw = f"{job_id}|{int(generation)}".encode("utf-8", "ignore")
        hv = int.from_bytes(hashlib.blake2s(raw, digest_size=8).digest(), "little", signed=False)
        return (hv % int(self.BEGIN_LOG_EVERY_N_ROUNDS)) == 0

    def begin(
        self,
        *,
        hash_into, vm, blob_buf, out_buf,
        job_id: str, generation: int, target64: int,
        expected_hashes: int, enable_summary_log: bool = False,
        force_log: bool = False,
    ) -> None:
        # Local var hoisting for rapid state reset
        self._hash_into = hash_into
        self._vm = vm
        self._blob_buf = blob_buf
        self._out_buf = out_buf
        self._job_id = str(job_id)
        self._generation = int(generation)
        self._target64 = self._u64(target64)
        self._expected_hashes = max(0, int(expected_hashes))

        # Fast reset
        self._hashes = 0
        self._hits = 0
        self._failures = 0
        self._consecutive_failures = 0
        self._best_tail64 = 0xFFFFFFFFFFFFFFFF
        self._best_nonce_u32 = -1
        self._last_error = ""
        self._opened_at = time.perf_counter()
        self._active = True
        self._summary_enabled = bool(enable_summary_log)
        self._warmed = False
        self._last_hit_logged_tail64 = 0xFFFFFFFFFFFFFFFF

        # Bucket calc
        bucket = self._count_bucket(self._expected_hashes)

        round_changed = (
            (self._job_id != self._last_logged_job) or
            (self._generation != self._last_logged_generation) or
            (bucket != self._last_logged_bucket)
        )

        if round_changed:
            self._logged_begin_for_current_round = False

        should_attempt_begin = (
            force_log or (
                round_changed and not self._logged_begin_for_current_round and
                self._should_sample_begin_round(
                    job_id=self._job_id,
                    generation=self._generation,
                    expected_hashes=self._expected_hashes,
                    force_log=force_log,
                )
            )
        )

        if should_attempt_begin:
            # Inline details for slightly less tuple creation overhead
            details = (
                f"job={self._job_id} gen={self._generation} "
                f"owner={self.owner_key} expected={self._expected_hashes}"
            )
            emitted = self._job_evt_emit(
                "begin", details=details, cooldown=60.0, force=force_log,
            )
            if emitted:
                self._logged_begin_for_current_round = True

        # Update last logged for next round
        self._last_logged_job = self._job_id
        self._last_logged_generation = self._generation
        self._last_logged_bucket = bucket
        self._seen_any_begin = True

    def warmup(self) -> None:
        if not self._active or self._hash_into is None:
            raise RuntimeError("RxHashAdvanceLane is not active")
        if self._warmed:
            return

        try:
            self._hash_into(self._vm, self._blob_buf, self._out_buf)
        except Exception as e:
            self._failures += 1
            self._consecutive_failures += 1
            self._last_error = f"{type(e).__name__}: {e}"
            # Local var cache for error details
            err_msg = (
                f"owner={self.owner_key} job={self._job_id} gen={self._generation} "
                f"phase=warmup failures={self._failures} err={self._last_error[:220]}"
            )
            self._class_evt_emit("error", details=err_msg, cooldown=90.0)
            raise

        self._warmed = True
        # Local var cache for warmup details
        wmsg = f"owner={self.owner_key} job={self._job_id} gen={self._generation}"
        self._owner_evt_emit("warmup", details=wmsg, cooldown=80.0)

    # --- OPTIMIZED: Core Hash Function (Hot Path) ---
    def hash_once(self) -> int:
        if not self._active or self._hash_into is None:
            raise RuntimeError("RxHashAdvanceLane is not active")

        try:
            self._hash_into(self._vm, self._blob_buf, self._out_buf)
        except Exception as e:
            self._failures += 1
            self._consecutive_failures += 1
            self._last_error = f"{type(e).__name__}: {e}"
            err_msg = (
                f"owner={self.owner_key} job={self._job_id} gen={self._generation} "
                f"failures={self._failures} consecutive={self._consecutive_failures} "
                f"err={self._last_error[:220]}"
            )
            self._class_evt_emit("error", details=err_msg, cooldown=90.0)
            raise

        self._hashes += 1
        self._consecutive_failures = 0

        # Optimized Progress Check (Minimize dot access)
        if self._hashes in (262144, 1048576, 4194304, 16777216):
            elapsed = max(1e-9, time.perf_counter() - self._opened_at)
            # Format HPS string directly for logging
            hps_str = f"{(self._hashes / elapsed):.2f}"
            prog_msg = (
                f"owner={self.owner_key} job={self._job_id} gen={self._generation} "
                f"hashes={self._hashes} hps={hps_str}"
            )
            self._owner_evt_emit("progress", details=prog_msg, cooldown=120.0)

        return self._tail64_fast(self._out_buf)

    # --- OPTIMIZED: Main Loop (Critical for Profit) ---
    def hash_loop(
            self,
            *,
            count: int, write_next_nonce, batch, stop_flag,
            stale_mask: int, is_current, job_id: str,
            generation: int,
    ) -> int:
        done = 0

        target64 = int(self._target64) & 0xFFFFFFFFFFFFFFFF
        out_buf = self._out_buf
        hash_into = self._hash_into

        best_tail64 = int(self._best_tail64) & 0xFFFFFFFFFFFFFFFF
        best_nonce = int(self._best_nonce_u32)
        hits = int(self._hits)
        last_hit = int(self._last_hit_logged_tail64)

        owner = self.owner_key
        j_id = self._job_id
        j_gen = int(self._generation)

        if hash_into is None or out_buf is None:
            self._last_error = "hash_loop called while lane is not active"
            return 0

        safe_count = max(0, int(count or 0))
        safe_stale_mask = int(stale_mask or 0)

        for i in range(safe_count):
            if stop_flag.is_set():
                break

            if safe_stale_mask >= 0 and (i & safe_stale_mask) == 0:
                if not is_current(job_id, generation):
                    break

            nonce_u32 = write_next_nonce()
            if nonce_u32 is None:
                break

            # IMPORTANT:
            # randomx.hash_into usually writes the hash into out_buf and returns None.
            # So do not trust its return value as tail64.
            maybe_tail64 = hash_into(self._vm, self._blob_buf, out_buf)

            if maybe_tail64 is None:
                tail64 = self._tail64_fast(out_buf)
            else:
                tail64 = int(maybe_tail64) & 0xFFFFFFFFFFFFFFFF

            done += 1

            if tail64 < target64:
                hits += 1

                if tail64 < best_tail64:
                    old_best = best_tail64
                    best_tail64 = tail64
                    best_nonce = int(nonce_u32) & 0xFFFFFFFF

                    should_log_hit = False
                    if self._summary_enabled:
                        if last_hit == 0xFFFFFFFFFFFFFFFF:
                            should_log_hit = True
                        elif old_best < 0xFFFFFFFFFFFFFFFF:
                            if float(tail64) <= float(old_best) * self.HIT_LOG_MIN_IMPROVEMENT_RATIO:
                                should_log_hit = True

                    if should_log_hit:
                        hit_msg = (
                            f"owner={owner} job={j_id} gen={j_gen} "
                            f"hits={hits} best_nonce={best_nonce} best_tail64={int(tail64)}"
                        )
                        emitted = self._owner_evt_emit("hit", details=hit_msg, cooldown=60.0)
                        if emitted:
                            last_hit = int(tail64)

                batch.offer(
                    nonce_u32=int(nonce_u32) & 0xFFFFFFFF,
                    hash_hex=bytes(out_buf).hex(),
                    tail64=int(tail64) & 0xFFFFFFFFFFFFFFFF,
                )

        # Write local hot-loop state back to the object.
        self._hashes += int(done)
        self._hits = int(hits)
        self._best_tail64 = int(best_tail64) & 0xFFFFFFFFFFFFFFFF
        self._best_nonce_u32 = int(best_nonce)
        self._last_hit_logged_tail64 = int(last_hit) & 0xFFFFFFFFFFFFFFFF
        self._consecutive_failures = 0

        return done

    def finish(self, *, done_hashes: Optional[int] = None) -> None:
        done = self._hashes if done_hashes is None else max(0, int(done_hashes))
        elapsed = max(0.0, time.perf_counter() - self._opened_at)
        hps = (float(done) / elapsed) if elapsed > 0.0 else 0.0

        # Optimized finish check
        should_log_finish = (
            self._summary_enabled and (
                self._hits > 0 or self._failures > 0 or done >= self.FINISH_LOG_MIN_HASHES
            )
        )

        if should_log_finish:
            finish_msg = (
                f"job={self._job_id} gen={self._generation} "
                f"owner={self.owner_key} done={done} hits={self._hits} failures={self._failures} "
                f"best_nonce={self._best_nonce_u32} best_tail64={self._best_tail64} "
                f"elapsed={elapsed:.6f}s hps={hps:.2f}"
            )
            self._job_evt_emit("finish", details=finish_msg, cooldown=60.0)

        self._active = False

    def clear(self) -> None:
        had_state = self._active or self._hashes > 0 or self._failures > 0

        old_job = self._job_id
        old_generation = self._generation
        old_hashes = self._hashes
        old_hits = self._hits
        old_failures = self._failures

        # Fast state reset
        self._hash_into = None
        self._vm = None
        self._blob_buf = None
        self._out_buf = None
        self._job_id = ""
        self._generation = 0
        self._target64 = 0xFFFFFFFFFFFFFFFF
        self._expected_hashes = 0
        self._hashes = 0
        self._hits = 0
        self._failures = 0
        self._consecutive_failures = 0
        self._best_tail64 = 0xFFFFFFFFFFFFFFFF
        self._best_nonce_u32 = -1
        self._last_error = ""
        self._opened_at = 0.0
        self._active = False
        self._summary_enabled = False
        self._warmed = False
        self._last_hit_logged_tail64 = 0xFFFFFFFFFFFFFFFF

        # Clear log if significant work done
        if had_state and (old_hashes >= 1048576 or old_failures > 0 or old_hits > 0):
            clear_msg = (
                f"owner={self.owner_key} last_job={old_job} "
                f"last_gen={old_generation} hashes={old_hashes} "
                f"hits={old_hits} failures={old_failures}"
            )
            self._owner_evt_emit("clear", details=clear_msg, cooldown=120.0)

    def snapshot(self) -> dict:
        elapsed = max(0.0, time.perf_counter() - self._opened_at) if self._opened_at > 0.0 else 0.0
        hps = (float(self._hashes) / elapsed) if elapsed > 0.0 else 0.0
        return {
            "owner_key": self.owner_key, "worker_index": self.worker_index,
            "job_id": self._job_id, "generation": self._generation,
            "expected_hashes": self._expected_hashes, "hashes": self._hashes,
            "hits": self._hits, "failures": self._failures,
            "consecutive_failures": self._consecutive_failures,
            "best_tail64": self._best_tail64, "best_nonce_u32": self._best_nonce_u32,
            "last_error": self._last_error, "elapsed_sec": elapsed,
            "hps_est": hps, "active": self._active,
        }

class _Tail64Probe(_ClassEventLogMixin):
    """
    Hot-path-safe tail64 reader for RandomX output buffers.

    Keeps old public usage working:
        probe.begin(job_id=..., generation=..., target64=...)
        tail64 = probe.read_tail64(out_buf)
        probe.note_hit(nonce_u32=nonce_u32, tail64=tail64)
        probe.finish(done_hashes=done)

    New patch behavior:
        - tracks best share per worker/generation
        - tracks duplicate nonce/share candidates
        - validates generation-scoped nonce windows
        - preserves worker/lane metadata for callback-layer debugging
        - can annotate native candidates with worker/generation/lane metadata
        - provides round-robin candidate distribution helper
        - lower tail64 is treated as better
    """

    __slots__ = (
        "worker_index",
        "owner_key",
        "_job_id",
        "_generation",
        "_target64",
        "_reads",
        "_hits",
        "_bad_reads",
        "_best_tail64",
        "_best_nonce_u32",
        "_best_logged_tail64",
        "_summary_enabled",
        "_active",
        "_thread_id",
        "_lane_id",
        "_start_nonce",
        "_stride",
        "_count",
        "_window_enabled",
        "_window_checked",
        "_window_bad",
        "_duplicate_nonce_hits",
        "_duplicate_candidate_hits",
        "_seen_nonces",
        "_seen_candidates",
        "_thread_winners",
        "_best_candidate",
        "_last_round_robin",
        "_last_snapshot",
    )

    _GLOBAL_EVT_MU = threading.RLock()
    _GLOBAL_EVT_NEXT_AT: dict[tuple[str, str], float] = {}
    _GLOBAL_EVT_SUPPRESSED: dict[tuple[str, str], int] = {}

    def __init__(
        self,
        *,
        worker_index: Optional[int] = None,
        owner_key: Optional[str] = None,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.worker_index = None if worker_index is None else int(worker_index)
        self.owner_key = (
            str(owner_key)
            if owner_key is not None
            else (f"worker-{self.worker_index}" if self.worker_index is not None else "tail64-probe")
        )

        self._job_id = ""
        self._generation = 0
        self._target64 = 0xFFFFFFFFFFFFFFFF
        self._reads = 0
        self._hits = 0
        self._bad_reads = 0
        self._best_tail64 = 0xFFFFFFFFFFFFFFFF
        self._best_nonce_u32 = -1
        self._best_logged_tail64 = 0xFFFFFFFFFFFFFFFF
        self._summary_enabled = False
        self._active = False

        self._thread_id = -1 if self.worker_index is None else int(self.worker_index)
        self._lane_id = -1
        self._start_nonce = 0
        self._stride = 1
        self._count = 0
        self._window_enabled = False
        self._window_checked = 0
        self._window_bad = 0

        self._duplicate_nonce_hits = 0
        self._duplicate_candidate_hits = 0
        self._seen_nonces: set[int] = set()
        self._seen_candidates: set[tuple[int, int]] = set()

        # {(generation, worker_id): best_record}
        self._thread_winners: dict[tuple[int, int], dict] = {}
        self._best_candidate: Optional[dict] = None

        self._last_round_robin: dict = {
            "input": 0,
            "output": 0,
            "threads": 1,
            "source_thread_counts": {},
            "assigned_thread_counts": {},
        }

        self._last_snapshot: dict = {}

        self._evt_init(
            class_prefix="Tail64Probe",
            logger=logger,
            cooldowns={
                "bad_read": 120.0,
                "best_hit": 30.0,
                "summary": 60.0,
                "clear": 120.0,
                "window_bad": 60.0,
                "duplicate": 90.0,
                "thread_winner": 60.0,
                "round_robin": 75.0,
            },
            phrases={
                "bad_read": [
                    "the tail reader stepped around a malformed buffer",
                    "tail64 extraction hit an unexpected buffer shape",
                    "the tail probe caught a bad output frame",
                    "a broken tail64 read was safely discarded",
                ],
                "best_hit": [
                    "a sharper tail64 surfaced on this lane",
                    "the worker found a better tail64 than before",
                    "a cleaner tail64 rose to the top of this run",
                    "the tail probe saw a new personal best",
                ],
                "summary": [
                    "the tail reader wrapped up a useful run",
                    "tail64 tracking settled out for this slice",
                    "the tail probe finished a productive pass",
                    "this tail64 pass came in with useful signal",
                ],
                "clear": [
                    "the tail probe cooled back to idle",
                    "tail64 tracking was released",
                    "the active tail reader stood down",
                    "tail64 state went quiet again",
                ],
                "window_bad": [
                    "a nonce landed outside its expected lane window",
                    "the tail probe caught a lane-window mismatch",
                    "nonce-window validation found an unexpected value",
                    "a worker candidate did not match its generation window",
                ],
                "duplicate": [
                    "a repeated nonce candidate was seen on this lane",
                    "the tail probe noticed a duplicate candidate echo",
                    "duplicate share metadata appeared in this worker slice",
                    "a repeated candidate was safely counted and ignored",
                ],
                "thread_winner": [
                    "a worker held onto its best generation candidate",
                    "one worker's strongest share was tracked",
                    "a per-thread winner was recorded",
                    "the tail probe marked a worker's best nonce",
                ],
                "round_robin": [
                    "tail candidates were interleaved across worker lanes",
                    "candidate winners were distributed by source thread",
                    "the tail probe balanced winners for parallel submission",
                    "unique share candidates were spread across submit lanes",
                ],
            },
        )

    @staticmethod
    def _u32(v: int) -> int:
        return int(v) & 0xFFFFFFFF

    @staticmethod
    def _u64(v: int) -> int:
        return int(v) & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def _share_diff_est(tail64: int) -> float:
        tail64 = int(tail64) & 0xFFFFFFFFFFFFFFFF
        if tail64 <= 0:
            return float("inf")
        return float((1 << 64) / tail64)

    @staticmethod
    def _tail64_from_hash_hex(hash_hex: str) -> int:
        try:
            h = bytes.fromhex(str(hash_hex).strip())
            if len(h) < 32:
                return 0xFFFFFFFFFFFFFFFF
            return int.from_bytes(h[24:32], "little", signed=False)
        except Exception:
            return 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def _sort_key_candidate(c: dict) -> tuple[int, int]:
        return (
            int(c.get("tail64", c.get("_tail64", 0xFFFFFFFFFFFFFFFF))) & 0xFFFFFFFFFFFFFFFF,
            int(c.get("nonce_u32", c.get("_nonce", 0))) & 0xFFFFFFFF,
        )

    @staticmethod
    def _clean_candidate(c: dict) -> dict:
        out = {
            "nonce_u32": int(c["nonce_u32"]) & 0xFFFFFFFF,
            "hash_hex": str(c.get("hash_hex", "")),
            "tail64": int(c["tail64"]) & 0xFFFFFFFFFFFFFFFF,
            "share_diff_est": float(
                c.get(
                    "share_diff_est",
                    _Tail64Probe._share_diff_est(int(c["tail64"])),
                )
            ),
        }

        # If no hash exists, keep the old code from failing by returning only
        # fields that actually exist.
        if not out["hash_hex"]:
            out.pop("hash_hex", None)

        return out

    def _global_evt_emit(
        self,
        key: str,
        *,
        details: str = "",
        cooldown: Optional[float] = None,
        phrases: Optional[list[str]] = None,
        force: bool = False,
        global_scope: str = "class",
    ) -> None:
        gate = (self._evt_prefix, str(key)) if global_scope == "class" else (self.owner_key, str(key))

        now = time.perf_counter()
        cd = float(
            self._evt_cooldowns.get(
                key,
                45.0 if cooldown is None else cooldown,
            )
        )

        with self._GLOBAL_EVT_MU:
            next_at = float(self._GLOBAL_EVT_NEXT_AT.get(gate, 0.0))
            if not force and now < next_at:
                self._GLOBAL_EVT_SUPPRESSED[gate] = int(
                    self._GLOBAL_EVT_SUPPRESSED.get(gate, 0)
                ) + 1
                return

            suppressed = int(self._GLOBAL_EVT_SUPPRESSED.pop(gate, 0))
            self._GLOBAL_EVT_NEXT_AT[gate] = now + cd

        phrase = self._evt_pick(key, phrases)
        extra = f" suppressed={suppressed}" if suppressed > 0 else ""

        if details:
            self._evt_write(f"[{self._evt_prefix}] {phrase} | {details}{extra}")
        else:
            self._evt_write(f"[{self._evt_prefix}] {phrase}{extra}")

    def begin(
        self,
        *,
        job_id: str,
        generation: int,
        target64: int,
        enable_summary_log: bool = False,
        start_nonce: Optional[int] = None,
        stride: Optional[int] = None,
        count: Optional[int] = None,
        lane_id: Optional[int] = None,
        thread_id: Optional[int] = None,
    ) -> None:
        """
        Backwards-compatible begin().

        New optional args allow generation-scoped nonce-window validation:
            start_nonce = assigned_start_nonce for this worker
            stride      = active thread count
            count       = assigned hash attempts for this worker
            lane_id     = residue lane id
            thread_id   = worker index
        """
        self._job_id = str(job_id)
        self._generation = int(generation)
        self._target64 = self._u64(target64)
        self._reads = 0
        self._hits = 0
        self._bad_reads = 0
        self._best_tail64 = 0xFFFFFFFFFFFFFFFF
        self._best_nonce_u32 = -1
        self._best_logged_tail64 = 0xFFFFFFFFFFFFFFFF
        self._summary_enabled = bool(enable_summary_log)
        self._active = True

        self._thread_id = (
            int(thread_id)
            if thread_id is not None
            else (-1 if self.worker_index is None else int(self.worker_index))
        )
        self._lane_id = int(lane_id) if lane_id is not None else self._lane_id

        self._duplicate_nonce_hits = 0
        self._duplicate_candidate_hits = 0
        self._seen_nonces.clear()
        self._seen_candidates.clear()
        self._best_candidate = None

        self._window_checked = 0
        self._window_bad = 0

        if start_nonce is not None and stride is not None and count is not None:
            self.set_nonce_window(
                start_nonce=start_nonce,
                stride=stride,
                count=count,
                lane_id=lane_id,
                thread_id=thread_id,
            )
        else:
            self._window_enabled = False
            self._start_nonce = 0
            self._stride = 1
            self._count = 0

    def set_nonce_window(
        self,
        *,
        start_nonce: int,
        stride: int,
        count: int,
        lane_id: Optional[int] = None,
        thread_id: Optional[int] = None,
    ) -> None:
        """
        Configure this worker's expected nonce lane.

        Expected sequence:
            nonce = start_nonce + k * stride, for 0 <= k < count

        uint32 wrap is handled by unsigned delta.
        """
        self._start_nonce = self._u32(start_nonce)
        self._stride = max(1, int(stride))
        self._count = max(0, int(count))
        self._window_enabled = self._count > 0

        if lane_id is not None:
            self._lane_id = int(lane_id)

        if thread_id is not None:
            self._thread_id = int(thread_id)

    def _nonce_in_window(self, nonce_u32: int) -> bool:
        if not self._window_enabled:
            return True

        nonce_u32 = self._u32(nonce_u32)
        delta = (nonce_u32 - self._start_nonce) & 0xFFFFFFFF

        if delta % self._stride != 0:
            return False

        index = delta // self._stride
        return 0 <= index < self._count

    @staticmethod
    def _read_tail64_fast(out_buf) -> int:
        """
        Read bytes 24..31 little-endian without allocating bytes(...).
        """
        return (
            int(out_buf[24])
            | (int(out_buf[25]) << 8)
            | (int(out_buf[26]) << 16)
            | (int(out_buf[27]) << 24)
            | (int(out_buf[28]) << 32)
            | (int(out_buf[29]) << 40)
            | (int(out_buf[30]) << 48)
            | (int(out_buf[31]) << 56)
        )

    def read_tail64(self, out_buf) -> int:
        """
        Hot-path reader.
        No normal logging here.
        Only rare anomaly logging if the buffer is not readable.
        """
        try:
            tail64 = self._read_tail64_fast(out_buf)
        except Exception:
            self._bad_reads += 1
            self._global_evt_emit(
                "bad_read",
                details=(
                    f"owner={self.owner_key} job={self._job_id} "
                    f"gen={self._generation} bad_reads={self._bad_reads}"
                ),
                global_scope="class",
            )
            return 0xFFFFFFFFFFFFFFFF

        self._reads += 1

        if tail64 < self._best_tail64:
            self._best_tail64 = int(tail64)

        return int(tail64)

    def _track_candidate_identity(self, *, nonce_u32: int, tail64: int) -> None:
        nonce_u32 = self._u32(nonce_u32)
        tail64 = self._u64(tail64)

        if nonce_u32 in self._seen_nonces:
            self._duplicate_nonce_hits += 1

        self._seen_nonces.add(nonce_u32)

        key = (nonce_u32, tail64)
        if key in self._seen_candidates:
            self._duplicate_candidate_hits += 1

        self._seen_candidates.add(key)

        if (
            self._duplicate_nonce_hits in (1, 2, 4, 8)
            or self._duplicate_candidate_hits in (1, 2, 4, 8)
        ):
            self._global_evt_emit(
                "duplicate",
                details=(
                    f"owner={self.owner_key} job={self._job_id} "
                    f"gen={self._generation} dup_nonce={self._duplicate_nonce_hits} "
                    f"dup_candidate={self._duplicate_candidate_hits}"
                ),
                global_scope="owner",
            )

        if len(self._seen_nonces) > 65536:
            self._seen_nonces = set(list(self._seen_nonces)[-8192:])

        if len(self._seen_candidates) > 65536:
            self._seen_candidates = set(list(self._seen_candidates)[-8192:])

    def _validate_hit_window(self, *, nonce_u32: int) -> None:
        if not self._window_enabled:
            return

        self._window_checked += 1

        if self._nonce_in_window(nonce_u32):
            return

        self._window_bad += 1

        if self._window_bad in (1, 2, 4, 8):
            end_hint = self._u32(self._start_nonce + max(0, self._count - 1) * self._stride)
            self._global_evt_emit(
                "window_bad",
                details=(
                    f"owner={self.owner_key} job={self._job_id} "
                    f"gen={self._generation} worker={self._thread_id} lane={self._lane_id} "
                    f"start={self._start_nonce} stride={self._stride} count={self._count} "
                    f"end_hint={end_hint} got={self._u32(nonce_u32)} "
                    f"window_bad={self._window_bad}"
                ),
                global_scope="owner",
            )

    def _track_thread_winner(self, candidate: dict) -> None:
        """
        Track best candidate per generation/worker.

        Lower tail64 is better.
        """
        try:
            gen = int(candidate.get("_generation", self._generation) or self._generation)
            worker_id = int(candidate.get("_found_by_thread", self._thread_id) or self._thread_id)
            lane_id = int(candidate.get("_lane_id", self._lane_id) or self._lane_id)
            tail64 = self._u64(candidate.get("tail64", candidate.get("_tail64", 0xFFFFFFFFFFFFFFFF)))
            nonce_u32 = self._u32(candidate.get("nonce_u32", candidate.get("_nonce", 0)))

            key = (gen, worker_id)
            prior = self._thread_winners.get(key)

            replace = False
            if prior is None:
                replace = True
            else:
                old_tail64 = self._u64(prior.get("tail64", 0xFFFFFFFFFFFFFFFF))
                old_nonce = self._u32(prior.get("nonce", 0xFFFFFFFF))

                if tail64 < old_tail64:
                    replace = True
                elif tail64 == old_tail64 and nonce_u32 < old_nonce:
                    replace = True

            if replace:
                self._thread_winners[key] = {
                    "candidate": dict(candidate),
                    "tail64": tail64,
                    "nonce": nonce_u32,
                    "lane_id": lane_id,
                    "worker_id": worker_id,
                    "generation": gen,
                }

                if tail64 < self._best_tail64:
                    self._best_tail64 = tail64
                    self._best_nonce_u32 = nonce_u32

                self._best_candidate = dict(candidate)

                if len(self._thread_winners) in (1, 2, 4, 8, 16):
                    self._global_evt_emit(
                        "thread_winner",
                        details=(
                            f"owner={self.owner_key} job={self._job_id} "
                            f"gen={gen} worker={worker_id} lane={lane_id} "
                            f"nonce={nonce_u32} tail64={tail64}"
                        ),
                        global_scope="owner",
                    )

            if len(self._thread_winners) > 8192:
                keys = sorted(self._thread_winners.keys(), key=lambda x: (x[0], x[1]))
                keep_keys = keys[-4096:]
                keep = {k: self._thread_winners[k] for k in keep_keys}
                self._thread_winners.clear()
                self._thread_winners.update(keep)

        except Exception:
            pass

    def note_hit(self, *, nonce_u32: int, tail64: int) -> None:
        """
        Call only on actual hits, not every hash.
        This keeps logging off the normal hot path.
        """
        self._hits += 1

        nonce_u32 = self._u32(nonce_u32)
        tail64 = self._u64(tail64)

        self._track_candidate_identity(nonce_u32=nonce_u32, tail64=tail64)
        self._validate_hit_window(nonce_u32=nonce_u32)

        candidate = {
            "nonce_u32": nonce_u32,
            "tail64": tail64,
            "share_diff_est": self._share_diff_est(tail64),
            "_found_by_thread": int(self._thread_id),
            "_generation": int(self._generation),
            "_lane_id": int(self._lane_id),
            "_tail64": tail64,
            "_nonce": nonce_u32,
        }

        self._track_thread_winner(candidate)

        if tail64 < self._best_tail64:
            self._best_tail64 = tail64
            self._best_nonce_u32 = int(nonce_u32)
        elif self._best_nonce_u32 < 0:
            self._best_nonce_u32 = int(nonce_u32)

        if not self._summary_enabled:
            return

        if tail64 < self._best_logged_tail64:
            self._best_logged_tail64 = tail64
            self._global_evt_emit(
                "best_hit",
                details=(
                    f"owner={self.owner_key} job={self._job_id} "
                    f"gen={self._generation} worker={self._thread_id} lane={self._lane_id} "
                    f"hits={self._hits} best_nonce={nonce_u32} best_tail64={tail64}"
                ),
                global_scope="owner",
            )

    def note_candidate(
        self,
        candidate: dict,
        *,
        found_by_thread: Optional[int] = None,
        lane_id: Optional[int] = None,
        generation: Optional[int] = None,
    ) -> Optional[dict]:
        """
        Track a full candidate dict returned by native hot loop.

        Returns an annotated copy that can be passed into _CandidateBatch or
        _CandidateSelector.

        This is useful in JITWorker callback:

            annotated = probe.note_candidate(c)
            if annotated:
                batch.merge_items([annotated])
        """
        try:
            if candidate is None:
                return None

            c = dict(candidate)

            nonce_u32 = self._u32(c.get("nonce_u32", c.get("_nonce", 0)))

            tail64 = c.get("tail64", c.get("_tail64", None))
            if tail64 is None:
                tail64 = self._tail64_from_hash_hex(str(c.get("hash_hex", "")))
            tail64 = self._u64(tail64)

            gen = int(generation if generation is not None else c.get("_generation", self._generation))
            worker_id = int(
                found_by_thread
                if found_by_thread is not None
                else c.get("_found_by_thread", self._thread_id)
            )
            lane = int(lane_id if lane_id is not None else c.get("_lane_id", self._lane_id))

            hash_hex = str(c.get("hash_hex", "") or "").strip().lower()

            out = {
                "nonce_u32": nonce_u32,
                "tail64": tail64,
                "share_diff_est": float(c.get("share_diff_est", self._share_diff_est(tail64))),
                "_found_by_thread": worker_id,
                "_generation": gen,
                "_lane_id": lane,
                "_tail64": tail64,
                "_nonce": nonce_u32,
            }

            if hash_hex:
                out["hash_hex"] = hash_hex

            self._track_candidate_identity(nonce_u32=nonce_u32, tail64=tail64)
            self._validate_hit_window(nonce_u32=nonce_u32)
            self._track_thread_winner(out)

            if tail64 < self._best_tail64:
                self._best_tail64 = tail64
                self._best_nonce_u32 = nonce_u32

            return out

        except Exception:
            return None

    def annotate_candidates(
        self,
        candidates: list[dict],
        *,
        found_by_thread: Optional[int] = None,
        lane_id: Optional[int] = None,
        generation: Optional[int] = None,
    ) -> list[dict]:
        out: list[dict] = []

        for c in candidates or []:
            annotated = self.note_candidate(
                c,
                found_by_thread=found_by_thread,
                lane_id=lane_id,
                generation=generation,
            )
            if annotated is not None:
                out.append(annotated)

        return out

    @staticmethod
    def round_robin_candidates(
        candidates: list[dict],
        *,
        threads: int,
        keep: Optional[int] = None,
        strip_debug: bool = False,
    ) -> list[dict]:
        """
        Distribute unique candidates across source threads.

        Lower tail64 is better.

        This helper is intentionally static so JITWorker can use it after
        collecting all worker candidates.
        """
        threads = max(1, int(threads))
        keep = max(1, int(keep if keep is not None else len(candidates or [])))

        best_by_nonce: dict[int, dict] = {}

        for raw in candidates or []:
            try:
                c = dict(raw)

                nonce_u32 = int(c.get("nonce_u32", c.get("_nonce", 0))) & 0xFFFFFFFF
                tail64 = int(c.get("tail64", c.get("_tail64", 0xFFFFFFFFFFFFFFFF))) & 0xFFFFFFFFFFFFFFFF

                c["nonce_u32"] = nonce_u32
                c["tail64"] = tail64
                c.setdefault("share_diff_est", _Tail64Probe._share_diff_est(tail64))
                c.setdefault("_nonce", nonce_u32)
                c.setdefault("_tail64", tail64)

                prior = best_by_nonce.get(nonce_u32)
                if prior is None:
                    best_by_nonce[nonce_u32] = c
                    continue

                prior_key = _Tail64Probe._sort_key_candidate(prior)
                new_key = _Tail64Probe._sort_key_candidate(c)

                if new_key < prior_key:
                    best_by_nonce[nonce_u32] = c

            except Exception:
                continue

        winners = list(best_by_nonce.values())
        if not winners:
            return []

        queues: dict[int, list[dict]] = {}

        for c in winners:
            try:
                source_thread = int(
                    c.get(
                        "_found_by_thread",
                        c.get("_worker_index", c.get("_thread_id", c.get("_lane_id", 0))),
                    )
                ) % threads
            except Exception:
                source_thread = int(c.get("nonce_u32", 0)) % threads

            queues.setdefault(source_thread, []).append(c)

        for q in queues.values():
            q.sort(key=_Tail64Probe._sort_key_candidate)

        source_order = sorted(
            queues.keys(),
            key=lambda tid: (
                _Tail64Probe._sort_key_candidate(queues[tid][0])
                if queues.get(tid)
                else (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF),
                tid,
            ),
        )

        out: list[dict] = []
        made_progress = True
        guard = 0

        while made_progress and len(out) < keep:
            made_progress = False

            for source_thread in source_order:
                q = queues.get(source_thread)
                if not q:
                    continue

                c = q.pop(0)
                c["_assigned_submit_thread"] = len(out) % threads
                out.append(c)
                made_progress = True

                if len(out) >= keep:
                    break

            guard += 1
            if guard > keep + threads + 4:
                break

        if strip_debug:
            return [_Tail64Probe._clean_candidate(c) for c in out]

        return out

    def finish(self, *, done_hashes: int) -> None:
        done_hashes = max(0, int(done_hashes))

        if self._summary_enabled and (
            self._hits > 0
            or self._bad_reads > 0
            or self._window_bad > 0
            or self._duplicate_nonce_hits > 0
        ):
            self._global_evt_emit(
                "summary",
                details=(
                    f"owner={self.owner_key} job={self._job_id} "
                    f"gen={self._generation} worker={self._thread_id} lane={self._lane_id} "
                    f"reads={self._reads} done={done_hashes} hits={self._hits} "
                    f"bad_reads={self._bad_reads} "
                    f"dup_nonce={self._duplicate_nonce_hits} "
                    f"dup_candidate={self._duplicate_candidate_hits} "
                    f"window_checked={self._window_checked} "
                    f"window_bad={self._window_bad} "
                    f"best_nonce={self._best_nonce_u32} "
                    f"best_tail64={self._best_tail64}"
                ),
                global_scope="owner",
            )

        self._active = False
        self._last_snapshot = self.snapshot()

    def clear(self) -> None:
        had_state = (
            self._active
            or self._reads > 0
            or self._hits > 0
            or self._bad_reads > 0
            or self._window_bad > 0
            or self._duplicate_nonce_hits > 0
        )

        old_job = self._job_id
        old_generation = self._generation
        old_reads = self._reads
        old_hits = self._hits
        old_window_bad = self._window_bad

        self._job_id = ""
        self._generation = 0
        self._target64 = 0xFFFFFFFFFFFFFFFF
        self._reads = 0
        self._hits = 0
        self._bad_reads = 0
        self._best_tail64 = 0xFFFFFFFFFFFFFFFF
        self._best_nonce_u32 = -1
        self._best_logged_tail64 = 0xFFFFFFFFFFFFFFFF
        self._summary_enabled = False
        self._active = False

        self._lane_id = -1
        self._start_nonce = 0
        self._stride = 1
        self._count = 0
        self._window_enabled = False
        self._window_checked = 0
        self._window_bad = 0

        self._duplicate_nonce_hits = 0
        self._duplicate_candidate_hits = 0
        self._seen_nonces.clear()
        self._seen_candidates.clear()
        self._thread_winners.clear()
        self._best_candidate = None

        self._last_round_robin = {
            "input": 0,
            "output": 0,
            "threads": 1,
            "source_thread_counts": {},
            "assigned_thread_counts": {},
        }

        if had_state and (old_hits > 0 or old_reads >= 1048576 or old_window_bad > 0):
            self._global_evt_emit(
                "clear",
                details=(
                    f"owner={self.owner_key} last_job={old_job} "
                    f"last_gen={old_generation} reads={old_reads} "
                    f"hits={old_hits} window_bad={old_window_bad}"
                ),
                global_scope="owner",
            )

    def snapshot(self) -> dict:
        winners: dict[str, dict] = {}

        for key, value in list(self._thread_winners.items())[-32:]:
            try:
                gen, worker_id = key
                winners[f"worker_{int(worker_id)}_gen_{int(gen)}"] = {
                    "nonce": int(value.get("nonce", 0)) & 0xFFFFFFFF,
                    "tail64": int(value.get("tail64", 0)) & 0xFFFFFFFFFFFFFFFF,
                    "tail64_hex": f"0x{int(value.get('tail64', 0)) & 0xFFFFFFFFFFFFFFFF:016X}",
                    "lane_id": int(value.get("lane_id", 0)),
                    "worker_id": int(worker_id),
                    "generation": int(gen),
                }
            except Exception:
                pass

        return {
            "owner_key": self.owner_key,
            "worker_index": self.worker_index,
            "thread_id": self._thread_id,
            "lane_id": self._lane_id,
            "job_id": self._job_id,
            "generation": self._generation,
            "target64": self._target64,
            "reads": self._reads,
            "hits": self._hits,
            "bad_reads": self._bad_reads,
            "best_tail64": self._best_tail64,
            "best_tail64_hex": f"0x{int(self._best_tail64) & 0xFFFFFFFFFFFFFFFF:016X}",
            "best_nonce_u32": self._best_nonce_u32,
            "active": self._active,
            "nonce_window": {
                "enabled": bool(self._window_enabled),
                "start_nonce": int(self._start_nonce),
                "stride": int(self._stride),
                "count": int(self._count),
                "checked": int(self._window_checked),
                "bad": int(self._window_bad),
            },
            "duplicates": {
                "nonce_hits": int(self._duplicate_nonce_hits),
                "candidate_hits": int(self._duplicate_candidate_hits),
                "seen_nonces": int(len(self._seen_nonces)),
                "seen_candidates": int(len(self._seen_candidates)),
            },
            "thread_winners_tracked": int(len(self._thread_winners)),
            "thread_winners": winners,
            "last_round_robin": dict(self._last_round_robin),
        }

class _NonceStrideWriter(_ClassEventLogMixin):
    """
    Per-worker nonce stream writer for the RandomX hot loop.

    Logging policy:
    - no log on every bind
    - no log on every slice refresh
    - bind logs only when:
        * first bind for this writer
        * job/generation changes
        * stride changes
        * count shape changes materially
        * forced explicitly
    - progress logs are sparse and globally throttled
    - wrap logs are globally throttled
    - clear logs are suppressed unless the writer actually did work
    """

    __slots__ = (
        "worker_index",
        "owner_key",
        "_nonce_ptr",
        "_job_id",
        "_generation",
        "_start_nonce",
        "_next_nonce",
        "_stride",
        "_count",
        "_writes",
        "_wraps",
        "_last_nonce",
        "_bound",
        "_seen_any_bind",
        "_last_bind_sig",
        "_last_logged_job",
        "_last_logged_generation",
        "_last_logged_stride",
        "_last_logged_count_bucket",
    )

    _GLOBAL_EVT_MU = threading.RLock()
    _GLOBAL_EVT_NEXT_AT: dict[tuple[str, str], float] = {}
    _GLOBAL_EVT_SUPPRESSED: dict[tuple[str, str], int] = {}

    def __init__(
        self,
        *,
        worker_index: Optional[int] = None,
        owner_key: Optional[str] = None,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.worker_index = None if worker_index is None else int(worker_index)
        self.owner_key = (
            str(owner_key)
            if owner_key is not None
            else (f"worker-{self.worker_index}" if self.worker_index is not None else "nonce-writer")
        )

        self._nonce_ptr = None
        self._job_id = ""
        self._generation = 0
        self._start_nonce = 0
        self._next_nonce = 0
        self._stride = 1
        self._count = 0
        self._writes = 0
        self._wraps = 0
        self._last_nonce: Optional[int] = None
        self._bound = False

        self._seen_any_bind = False
        self._last_bind_sig: Optional[tuple] = None
        self._last_logged_job = ""
        self._last_logged_generation = 0
        self._last_logged_stride = 0
        self._last_logged_count_bucket = -1

        self._evt_init(
            class_prefix="NonceStrideWriter",
            logger=logger,
            cooldowns={
                "bind": 45.0,
                "wrap": 60.0,
                "progress": 90.0,
                "clear": 120.0,
            },
            phrases={
                "bind": [
                    "nonce lane aligned with fresh work",
                    "the writer settled onto a new nonce shape",
                    "nonce ownership shifted onto a new slice",
                    "the nonce stream re-formed around new work",
                ],
                "wrap": [
                    "the nonce stream crossed the uint32 seam",
                    "nonce space wrapped under load",
                    "the writer rolled across the 32-bit edge",
                    "the nonce lane looped through its boundary",
                ],
                "progress": [
                    "the nonce lane has been advancing steadily",
                    "the writer has been chewing through a long run",
                    "nonce stepping continues through active work",
                    "the writer has built up real distance on this lane",
                ],
                "clear": [
                    "the nonce writer cooled back to idle",
                    "the active nonce stream was released",
                    "the writer stepped down from live work",
                    "nonce ownership went quiet again",
                ],
            },
        )

    @staticmethod
    def _u32(v: int) -> int:
        return int(v) & 0xFFFFFFFF

    @staticmethod
    def _count_bucket(count: int) -> int:
        count = max(0, int(count))
        if count <= 0:
            return 0
        if count <= 8:
            return 8
        if count <= 16:
            return 16
        if count <= 32:
            return 32
        if count <= 64:
            return 64
        if count <= 128:
            return 128
        if count <= 256:
            return 256
        if count <= 512:
            return 512
        return 1024

    def _global_evt_emit(
        self,
        key: str,
        *,
        details: str = "",
        cooldown: Optional[float] = None,
        phrases: Optional[list[str]] = None,
        force: bool = False,
        global_scope: str = "class",
    ) -> None:
        if global_scope == "owner":
            gate = (self.owner_key, str(key))
        else:
            gate = (self._evt_prefix, str(key))

        now = time.perf_counter()
        cd = float(
            self._evt_cooldowns.get(
                key,
                45.0 if cooldown is None else cooldown,
            )
        )

        suppressed = 0
        with self._GLOBAL_EVT_MU:
            next_at = float(self._GLOBAL_EVT_NEXT_AT.get(gate, 0.0))
            if not force and now < next_at:
                self._GLOBAL_EVT_SUPPRESSED[gate] = int(self._GLOBAL_EVT_SUPPRESSED.get(gate, 0)) + 1
                return

            suppressed = int(self._GLOBAL_EVT_SUPPRESSED.pop(gate, 0))
            self._GLOBAL_EVT_NEXT_AT[gate] = now + cd

        phrase = self._evt_pick(key, phrases)
        extra = f" suppressed={suppressed}" if suppressed > 0 else ""
        if details:
            self._evt_write(f"[{self._evt_prefix}] {phrase} | {details}{extra}")
        else:
            self._evt_write(f"[{self._evt_prefix}] {phrase}{extra}")

    def _should_log_bind(
        self,
        *,
        job_id: str,
        generation: int,
        stride: int,
        count: int,
        force_log: bool,
    ) -> bool:
        if force_log:
            return True

        count_bucket = self._count_bucket(count)

        if not self._seen_any_bind:
            return True

        if job_id != self._last_logged_job:
            return True

        if int(generation) != self._last_logged_generation:
            return True

        if int(stride) != self._last_logged_stride:
            return True

        if count_bucket != self._last_logged_count_bucket:
            return True

        return False

    def bind(
        self,
        *,
        nonce_ptr,
        start_nonce: int,
        stride: int,
        count: int,
        job_id: str = "",
        generation: int = 0,
        force_log: bool = False,
    ) -> None:
        job_id = str(job_id)
        generation = int(generation)
        start_nonce = self._u32(start_nonce)
        stride = max(1, int(stride))
        count = max(0, int(count))

        bind_sig = (job_id, generation, start_nonce, stride, count)

        self._nonce_ptr = nonce_ptr
        self._job_id = job_id
        self._generation = generation
        self._start_nonce = start_nonce
        self._next_nonce = start_nonce
        self._stride = stride
        self._count = count
        self._writes = 0
        self._wraps = 0
        self._last_nonce = None
        self._bound = True

        if count <= 0:
            self._last_bind_sig = bind_sig
            return

        should_log = self._should_log_bind(
            job_id=job_id,
            generation=generation,
            stride=stride,
            count=count,
            force_log=force_log,
        )

        if should_log:
            self._global_evt_emit(
                "bind",
                details=(
                    f"owner={self.owner_key} job={job_id} "
                    f"gen={generation} start={start_nonce} "
                    f"stride={stride} count={count}"
                ),
                force=force_log,
                global_scope="class",
            )
            self._last_logged_job = job_id
            self._last_logged_generation = generation
            self._last_logged_stride = stride
            self._last_logged_count_bucket = self._count_bucket(count)

        self._seen_any_bind = True
        self._last_bind_sig = bind_sig

    def clear(self) -> None:
        had_work = self._bound and (self._count > 0 or self._writes > 0)

        old_job = self._job_id
        old_generation = self._generation
        old_writes = self._writes
        old_wraps = self._wraps

        self._nonce_ptr = None
        self._job_id = ""
        self._generation = 0
        self._start_nonce = 0
        self._next_nonce = 0
        self._stride = 1
        self._count = 0
        self._writes = 0
        self._wraps = 0
        self._last_nonce = None
        self._bound = False

        if had_work and (old_writes >= 65536 or old_wraps > 0):
            self._global_evt_emit(
                "clear",
                details=(
                    f"owner={self.owner_key} last_job={old_job} "
                    f"last_gen={old_generation} writes={old_writes} wraps={old_wraps}"
                ),
                global_scope="owner",
            )

    def write_next(self) -> int:
        """
        Hot-path method.
        Writes the next nonce into nonce_ptr[0] and returns it.

        Keeps the fast path unchanged except for the stored rolling next_nonce.
        """
        if not self._bound or self._nonce_ptr is None:
            raise RuntimeError("NonceStrideWriter is not bound")

        nonce_u32 = self._next_nonce
        self._nonce_ptr[0] = nonce_u32

        next_nonce = (nonce_u32 + self._stride) & 0xFFFFFFFF
        self._next_nonce = next_nonce
        self._writes += 1

        if next_nonce < nonce_u32:
            self._wraps += 1
            self._global_evt_emit(
                "wrap",
                details=(
                    f"owner={self.owner_key} job={self._job_id} "
                    f"gen={self._generation} wraps={self._wraps} "
                    f"last_nonce={nonce_u32} next_nonce={next_nonce} stride={self._stride}"
                ),
                global_scope="class",
            )

        self._last_nonce = nonce_u32

        if self._writes in (65536, 262144, 1048576, 4194304):
            self._global_evt_emit(
                "progress",
                details=(
                    f"owner={self.owner_key} job={self._job_id} "
                    f"gen={self._generation} writes={self._writes} "
                    f"last_nonce={nonce_u32} stride={self._stride}"
                ),
                global_scope="owner",
            )

        return nonce_u32

    def nonce_for_index(self, i: int) -> int:
        i = max(0, int(i))
        return (self._start_nonce + (i * self._stride)) & 0xFFFFFFFF

    def snapshot(self) -> dict:
        return {
            "owner_key": self.owner_key,
            "worker_index": self.worker_index,
            "job_id": self._job_id,
            "generation": self._generation,
            "start_nonce": self._start_nonce,
            "next_nonce": self._next_nonce,
            "stride": self._stride,
            "count": self._count,
            "writes": self._writes,
            "wraps": self._wraps,
            "last_nonce": self._last_nonce,
            "bound": self._bound,
        }

class _ShareDiversityCoordinator(_ClassEventLogMixin):
    """
    Final-stage diversity chooser for JITWorker.

    Why this helps:
    - does not basic-dedupe every repeated proof forever
    - remembers recently returned proofs for a short TTL
    - softly prefers different nonce stripes before returning the same proof again
    - keeps tail64 as the main quality signal
    """

    def __init__(
        self,
        *,
        logger: Optional[Callable[[str], None]] = None,
        ttl_ms: float = 18000.0,
        max_recent: int = 8192,
        stripe_shift: int = 12,
    ) -> None:
        self.logger = logger or (lambda s: None)
        self.ttl_ms = max(1000.0, float(ttl_ms))
        self.max_recent = max(128, int(max_recent))
        self.stripe_shift = max(6, int(stripe_shift))

        self._mu = threading.RLock()
        self._recent: dict[str, tuple[float, int]] = {}  # proof_key -> (seen_at, count)
        self._last_job_id: str = ""
        self._last_generation: int = 0

        self._evt_init(
            class_prefix="ShareDiversity",
            logger=self.logger,
            cooldowns={
                "round": 30.0,
                "recent": 45.0,
                "stripe": 45.0,
                "picked": 20.0,
                "prune": 60.0,
            },
            phrases={
                "round": [
                    "a new return-shaping round opened",
                    "diversity tracking woke onto fresh work",
                    "the share-return shaper stepped into a new round",
                ],
                "recent": [
                    "recent proofs were held back briefly",
                    "the same proof trail was cooled off",
                    "fresh candidates were favored over echoes",
                ],
                "stripe": [
                    "nonce lanes were spread across the return set",
                    "the returned set reached across multiple nonce stripes",
                    "the selector leaned toward a wider nonce footprint",
                ],
                "picked": [
                    "a sharper diverse set rolled out",
                    "the round returned a more varied hit set",
                    "diversity shaping pushed a cleaner result set forward",
                ],
                "prune": [
                    "old return memory was swept away",
                    "stale proof memory was trimmed back",
                    "expired diversity memory was cleared",
                ],
            },
        )

    @staticmethod
    def _u32(v: int) -> int:
        return int(v) & 0xFFFFFFFF

    @staticmethod
    def _u64(v: int) -> int:
        return int(v) & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def _norm_hash_hex(v: Any) -> str:
        return str(v or "").strip().lower()

    def _now(self) -> float:
        return time.perf_counter()

    def _proof_key(
        self,
        *,
        job_id: str,
        generation: int,
        nonce_u32: int,
        hash_hex: str,
    ) -> str:
        raw = (
            f"{job_id}|{int(generation)}|{int(nonce_u32) & 0xFFFFFFFF}|{self._norm_hash_hex(hash_hex)}"
        ).encode("utf-8", "ignore")
        return hashlib.blake2s(raw, digest_size=16).hexdigest()

    def _prune_locked(self) -> None:
        now = self._now()
        ttl_sec = self.ttl_ms / 1000.0

        if not self._recent:
            return

        doomed = [k for k, (ts, _count) in self._recent.items() if (now - ts) >= ttl_sec]
        for k in doomed:
            self._recent.pop(k, None)

        if len(self._recent) > self.max_recent:
            ordered = sorted(self._recent.items(), key=lambda kv: (float(kv[1][0]), int(kv[1][1])))
            drop_n = len(self._recent) - self.max_recent
            for k, _ in ordered[:drop_n]:
                self._recent.pop(k, None)

        if doomed:
            self._evt_emit("prune", details=f"expired={len(doomed)} kept={len(self._recent)}")

    def begin_round(self, *, job_id: str, generation: int) -> None:
        job_id = str(job_id)
        generation = int(generation)

        with self._mu:
            if self._last_job_id != job_id or self._last_generation != generation:
                self._last_job_id = job_id
                self._last_generation = generation
                self._evt_emit(
                    "round",
                    details=f"job={job_id} gen={generation}",
                )
            self._prune_locked()

    def pick(
        self,
        *,
        job_id: str,
        generation: int,
        candidates: list[dict],
        max_results: int,
    ) -> list[dict]:
        keep = max(1, int(max_results))
        if not candidates:
            return []

        job_id = str(job_id)
        generation = int(generation)

        with self._mu:
            self._prune_locked()
            now = self._now()

            prepared: list[dict] = []
            for raw in candidates:
                try:
                    nonce_u32 = self._u32(raw["nonce_u32"])
                    hash_hex = self._norm_hash_hex(raw["hash_hex"])
                    tail64 = self._u64(raw["tail64"])
                    share_diff_est = float(raw.get("share_diff_est", 0.0))
                    if not hash_hex:
                        continue

                    proof_key = self._proof_key(
                        job_id=job_id,
                        generation=generation,
                        nonce_u32=nonce_u32,
                        hash_hex=hash_hex,
                    )
                    stripe = int(nonce_u32 >> self.stripe_shift)
                    recent_entry = self._recent.get(proof_key)
                    recent_seen = 1 if recent_entry is not None else 0
                    recent_count = int(recent_entry[1]) if recent_entry is not None else 0

                    item = dict(raw)
                    item["_proof_key"] = proof_key
                    item["_stripe"] = stripe
                    item["_recent_seen"] = recent_seen
                    item["_recent_count"] = recent_count
                    item["_tail64_int"] = int(tail64)
                    item["_nonce_u32_int"] = int(nonce_u32)
                    item["_share_diff_est_float"] = float(share_diff_est)
                    prepared.append(item)
                except Exception:
                    continue

            if not prepared:
                return []

            selected: list[dict] = []
            stripe_counts: dict[int, int] = {}

            while prepared and len(selected) < keep:
                best_idx: Optional[int] = None
                best_score: Optional[tuple] = None

                for idx, cand in enumerate(prepared):
                    stripe = int(cand["_stripe"])
                    recent_seen = int(cand["_recent_seen"])
                    recent_count = int(cand["_recent_count"])

                    same_stripe_pen = int(stripe_counts.get(stripe, 0))
                    near_stripe_pen = (
                        int(stripe_counts.get(stripe - 1, 0))
                        + int(stripe_counts.get(stripe + 1, 0))
                    )

                    # tuple order matters:
                    # 1) unseen proofs before recent echoes
                    # 2) lower repeat count before heavily resurfaced proofs
                    # 3) new stripes before already-used stripes
                    # 4) neighboring stripe crowding penalty
                    # 5) then tail64 quality
                    # 6) stable tie-break by nonce
                    score = (
                        recent_seen,
                        recent_count,
                        same_stripe_pen,
                        near_stripe_pen,
                        int(cand["_tail64_int"]),
                        int(cand["_nonce_u32_int"]),
                    )

                    if best_score is None or score < best_score:
                        best_score = score
                        best_idx = idx

                assert best_idx is not None
                chosen = prepared.pop(best_idx)

                stripe = int(chosen["_stripe"])
                proof_key = str(chosen["_proof_key"])

                stripe_counts[stripe] = int(stripe_counts.get(stripe, 0)) + 1

                self._recent[proof_key] = (now, int(self._recent.get(proof_key, (now, 0))[1]) + 1)

                out = {
                    "nonce_u32": int(chosen["nonce_u32"]),
                    "hash_hex": str(chosen["hash_hex"]),
                    "tail64": int(chosen["tail64"]),
                    "share_diff_est": float(chosen.get("share_diff_est", 0.0)),
                }
                selected.append(out)

            if selected:
                used_stripes = len({int(x["nonce_u32"]) >> self.stripe_shift for x in selected})
                if any(self._proof_key(
                    job_id=job_id,
                    generation=generation,
                    nonce_u32=int(x["nonce_u32"]),
                    hash_hex=str(x["hash_hex"]),
                ) in self._recent for x in selected):
                    self._evt_emit(
                        "recent",
                        details=f"selected={len(selected)} pool={len(candidates)}",
                    )
                if used_stripes > 1:
                    self._evt_emit(
                        "stripe",
                        details=f"selected={len(selected)} used_stripes={used_stripes}",
                    )

                best = selected[0]
                self._evt_emit(
                    "picked",
                    details=(
                        f"selected={len(selected)} pool={len(candidates)} "
                        f"best_nonce={int(best['nonce_u32'])} best_tail64={int(best['tail64'])}"
                    ),
                )

            return selected

class _CandidateBatch(_ClassEventLogMixin):
    """
    Fast candidate batch with sparse natural-event logging.

    Keeps the same public API:
    - __init__(owner_key, max_keep_default, logger)
    - reset(...)
    - offer(...)
    - offer_hit(...)
    - merge_items(...)
    - merge_exported(...)
    - export(...)

    New patch behavior:
    - keeps best candidate per nonce
    - preserves worker/thread/lane metadata internally
    - tracks per-thread winners per generation
    - exports unique nonce winners in round-robin worker order
    - keeps debug snapshot data for nonce/share validation
    - does not mutate blob, seed, RandomX state, or candidate hashes
    """

    __slots__ = (
        "owner_key",
        "max_keep_default",
        "_job_id",
        "_generation",
        "_requested_keep",
        "_best_by_nonce",
        "_incoming",
        "_accepted",
        "_rejected_same_or_worse",
        "_replaced",
        "_bad",
        "_merge_calls",
        "_dirty",
        "_cached_keep",
        "_cached_out",
        "_opened_logged",
        "_last_export_sig",
        "_owner_thread_id",
        "_thread_winners",
        "_source_thread_counts",
        "_assigned_thread_counts",
        "_duplicate_candidate_count",
        "_duplicate_tail64_count",
        "_last_threads_inferred",
        "_last_snapshot",
    )

    _GLOBAL_EVT_MU = threading.RLock()
    _GLOBAL_EVT_NEXT_AT: dict[tuple[str, str], float] = {}
    _GLOBAL_EVT_SUPPRESSED: dict[tuple[str, str], int] = {}

    def __init__(
        self,
        *,
        owner_key: str,
        max_keep_default: int = 16,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.owner_key = str(owner_key)
        self.max_keep_default = max(1, int(max_keep_default))

        self._job_id: str = ""
        self._generation: int = 0
        self._requested_keep: int = self.max_keep_default

        # nonce_u32 -> normalized candidate dict.
        #
        # Candidate dict keeps:
        #   nonce_u32
        #   hash_hex
        #   tail64
        #   share_diff_est
        #
        # Plus optional debug metadata:
        #   _found_by_thread
        #   _generation
        #   _lane_id
        #   _assigned_submit_thread
        self._best_by_nonce: dict[int, dict] = {}

        self._incoming = 0
        self._accepted = 0
        self._rejected_same_or_worse = 0
        self._replaced = 0
        self._bad = 0
        self._merge_calls = 0

        self._dirty = True
        self._cached_keep = 0
        self._cached_out: list[dict] = []

        self._opened_logged = False
        self._last_export_sig: Optional[tuple] = None

        self._owner_thread_id = self._parse_owner_thread_id(self.owner_key)

        # {(generation, worker_id): best_candidate_record}
        self._thread_winners: dict[tuple[int, int], dict] = {}

        self._source_thread_counts: dict[int, int] = {}
        self._assigned_thread_counts: dict[int, int] = {}
        self._duplicate_candidate_count = 0
        self._duplicate_tail64_count = 0
        self._last_threads_inferred = 1
        self._last_snapshot: dict = {
            "owner": self.owner_key,
            "job_id": "",
            "generation": 0,
            "incoming": 0,
            "accepted": 0,
            "rejected_same_or_worse": 0,
            "replaced": 0,
            "bad": 0,
            "merge_calls": 0,
            "unique_nonce_winners": 0,
            "exported": 0,
            "threads_inferred": 1,
            "source_thread_counts": {},
            "assigned_thread_counts": {},
            "duplicate_candidate_count": 0,
            "duplicate_tail64_count": 0,
            "thread_winners_tracked": 0,
        }

        self._evt_init(
            class_prefix="CandidateBatch",
            logger=logger,
            cooldowns={
                "batch_open": 45.0,
                "burst": 60.0,
                "replace": 75.0,
                "merge": 60.0,
                "round_robin": 75.0,
                "thread_winner": 75.0,
                "trim": 75.0,
                "flush": 60.0,
                "bad": 90.0,
            },
            phrases={
                "batch_open": [
                    "a candidate lane opened up",
                    "the batch woke onto a fresh round",
                    "a new candidate window came online",
                    "the batch stepped onto live work",
                ],
                "burst": [
                    "a cluster of live hits started to form",
                    "candidate traffic began to gather",
                    "the batch started catching real movement",
                    "a pocket of valid hits came together",
                ],
                "replace": [
                    "a stronger nonce echo displaced an older one",
                    "the batch upgraded a repeated nonce",
                    "a sharper candidate replaced weaker footing",
                    "one nonce came back stronger than before",
                ],
                "merge": [
                    "worker candidate streams folded together",
                    "the round batch absorbed several worker hits",
                    "candidate lanes merged into one stronger view",
                    "multiple hit streams were gathered into one batch",
                ],
                "round_robin": [
                    "unique nonce winners were spread across worker lanes",
                    "candidate winners were balanced by source thread",
                    "the batch interleaved workers before export",
                    "ranked candidates were distributed across active lanes",
                ],
                "thread_winner": [
                    "a worker held onto its best generation candidate",
                    "one worker's strongest share was tracked",
                    "a per-thread winner was recorded",
                    "the batch marked a worker's best nonce",
                ],
                "trim": [
                    "the batch trimmed itself to the sharpest edges",
                    "weaker candidates were left behind at the boundary",
                    "the kept set narrowed to the best slice",
                    "the batch cut back to its strongest core",
                ],
                "flush": [
                    "the batch handed off its strongest candidates",
                    "a filtered candidate set rolled forward",
                    "the batch exported its sharpest results",
                    "the kept candidates were pushed onward",
                ],
                "bad": [
                    "some malformed candidates were ignored",
                    "the batch stepped around damaged entries",
                    "broken candidate records were filtered out",
                    "invalid candidate shapes were discarded",
                ],
            },
        )

    @staticmethod
    def _parse_owner_thread_id(owner_key: str) -> int:
        """
        Extract worker id from names like:
            worker-batch-0
            worker-batch-7
            JITWorker-3

        Returns -1 when not found.
        """
        try:
            text = str(owner_key or "").strip()
            parts = text.replace("_", "-").split("-")

            for part in reversed(parts):
                if part.isdigit():
                    return int(part)

            return -1
        except Exception:
            return -1

    @staticmethod
    def _share_diff_est(tail64: int) -> float:
        if tail64 <= 0:
            return float("inf")
        return float((1 << 64) / tail64)

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
    def _heap_key(nonce_u32: int, tail64: int) -> tuple[int, int]:
        """
        Heap stores the current worst kept entry at index 0.
        More positive is better for replacement testing.
        """
        return (-int(tail64), -int(nonce_u32))

    @staticmethod
    def _sort_key_dict(c: dict) -> tuple[int, int]:
        return int(c["tail64"]), int(c["nonce_u32"])

    @staticmethod
    def _is_better(a: dict, b: dict) -> bool:
        """
        Lower tail64 is better.
        Lower nonce is stable tie-break.
        """
        at = int(a["tail64"])
        bt = int(b["tail64"])
        if at != bt:
            return at < bt
        return int(a["nonce_u32"]) < int(b["nonce_u32"])

    @staticmethod
    def _safe_int(value, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return int(default)

    @staticmethod
    def _read_env_threads(default: int = 1) -> int:
        try:
            import os

            for name in (
                "JITWORKER_SELECTOR_THREADS",
                "MONERO_SELECTOR_THREADS",
                "JITWORKER_THREADS",
                "MONERO_THREADS",
            ):
                raw = os.getenv(name)
                if raw is None:
                    continue

                try:
                    value = int(str(raw).strip())
                    if value > 0:
                        return value
                except Exception:
                    continue
        except Exception:
            pass

        return max(1, int(default))

    def _mark_dirty(self) -> None:
        self._dirty = True
        self._cached_keep = 0
        self._cached_out = []

    def _is_round_batch(self) -> bool:
        return self.owner_key == "round-batch"

    def _global_evt_emit(
        self,
        key: str,
        *,
        details: str = "",
        cooldown: Optional[float] = None,
        phrases: Optional[list[str]] = None,
        force: bool = False,
    ) -> None:
        gate = (self.owner_key, str(key))
        now = time.perf_counter()
        cd = float(
            self._evt_cooldowns.get(
                key,
                45.0 if cooldown is None else cooldown,
            )
        )

        with self._GLOBAL_EVT_MU:
            next_at = float(self._GLOBAL_EVT_NEXT_AT.get(gate, 0.0))
            if not force and now < next_at:
                self._GLOBAL_EVT_SUPPRESSED[gate] = int(
                    self._GLOBAL_EVT_SUPPRESSED.get(gate, 0)
                ) + 1
                return

            suppressed = int(self._GLOBAL_EVT_SUPPRESSED.pop(gate, 0))
            self._GLOBAL_EVT_NEXT_AT[gate] = now + cd

        phrase = self._evt_pick(key, phrases)
        extra = f" suppressed={suppressed}" if suppressed > 0 else ""

        if details:
            self._evt_write(f"[{self._evt_prefix}] {phrase} | {details}{extra}")
        else:
            self._evt_write(f"[{self._evt_prefix}] {phrase}{extra}")

    def _normalize_candidate(self, raw: dict) -> Optional[dict]:
        """
        Normalize one candidate and preserve worker/lane/generation metadata.
        """
        try:
            if raw is None:
                return None

            nonce_u32 = int(raw.get("nonce_u32", 0)) & 0xFFFFFFFF

            hash_hex = str(raw.get("hash_hex", "") or "").strip().lower()
            if not hash_hex:
                return None

            tail64 = raw.get("tail64", None)
            if tail64 is None:
                tail64 = raw.get("_tail64", None)
            if tail64 is None:
                tail64 = self._tail64_from_hash_hex(hash_hex)
            tail64 = int(tail64) & 0xFFFFFFFFFFFFFFFF

            share_diff_est = raw.get("share_diff_est", None)
            if share_diff_est is None:
                share_diff_est = self._share_diff_est(tail64)
            share_diff_est = float(share_diff_est)

            out = {
                "nonce_u32": nonce_u32,
                "hash_hex": hash_hex,
                "tail64": tail64,
                "share_diff_est": share_diff_est,
            }

            # Preserve metadata for thread-aware export.
            for key in (
                "_found_by_thread",
                "_worker_index",
                "_thread_id",
                "_generation",
                "_lane_id",
                "_assigned_submit_thread",
                "_tail64",
                "_nonce",
                "worker_index",
                "thread_id",
                "lane_id",
                "generation",
            ):
                if key in raw:
                    out[key] = raw.get(key)

            # Fill metadata defaults.
            if "_generation" not in out:
                out["_generation"] = int(self._generation)

            if "_found_by_thread" not in out:
                if self._owner_thread_id >= 0:
                    out["_found_by_thread"] = int(self._owner_thread_id)
                elif "worker_index" in out:
                    out["_found_by_thread"] = self._safe_int(out.get("worker_index"), 0)
                elif "thread_id" in out:
                    out["_found_by_thread"] = self._safe_int(out.get("thread_id"), 0)

            if "_lane_id" not in out:
                if "lane_id" in out:
                    out["_lane_id"] = self._safe_int(out.get("lane_id"), 0)
                elif "_found_by_thread" in out:
                    out["_lane_id"] = self._safe_int(out.get("_found_by_thread"), 0)

            out["_tail64"] = tail64
            out["_nonce"] = nonce_u32

            return out
        except Exception:
            return None

    def _candidate_source_thread(self, cand: dict, threads: int) -> int:
        threads = max(1, int(threads))

        for key in (
            "_found_by_thread",
            "_worker_index",
            "_thread_id",
            "worker_index",
            "thread_id",
            "_lane_id",
            "lane_id",
        ):
            if key not in cand:
                continue

            try:
                value = int(cand.get(key))
                if value >= 0:
                    return value % threads
            except Exception:
                continue

        if self._owner_thread_id >= 0:
            return int(self._owner_thread_id) % threads

        try:
            return int(cand["nonce_u32"]) % threads
        except Exception:
            return 0

    def _infer_thread_count(self, winners: list[dict]) -> int:
        max_seen = -1

        for cand in winners or []:
            for key in (
                "_found_by_thread",
                "_worker_index",
                "_thread_id",
                "worker_index",
                "thread_id",
                "_lane_id",
                "lane_id",
            ):
                if key not in cand:
                    continue

                try:
                    value = int(cand.get(key))
                    if value >= 0:
                        max_seen = max(max_seen, value)
                except Exception:
                    pass

        if max_seen >= 0:
            return max(1, max_seen + 1)

        env_threads = self._read_env_threads(default=1)
        return max(1, int(env_threads))

    def _track_thread_winner(self, cand: dict) -> None:
        """
        Keep the best candidate per generation/worker.
        """
        try:
            gen = int(cand.get("_generation", self._generation) or self._generation)
            worker_id = self._candidate_source_thread(cand, self._last_threads_inferred)

            key = (gen, worker_id)
            prior = self._thread_winners.get(key)

            if prior is None or self._is_better(cand, prior["candidate"]):
                self._thread_winners[key] = {
                    "candidate": dict(cand),
                    "tail64": int(cand["tail64"]) & 0xFFFFFFFFFFFFFFFF,
                    "nonce": int(cand["nonce_u32"]) & 0xFFFFFFFF,
                    "lane_id": int(cand.get("_lane_id", worker_id) or 0),
                    "worker_id": int(worker_id),
                    "generation": int(gen),
                }

                if len(self._thread_winners) in (1, 2, 4, 8, 16):
                    self._global_evt_emit(
                        "thread_winner",
                        details=(
                            f"owner={self.owner_key} job={self._job_id} "
                            f"gen={gen} worker={worker_id} "
                            f"nonce={int(cand['nonce_u32'])} "
                            f"tail64={int(cand['tail64'])}"
                        ),
                    )

            # Bound memory to recent generations.
            if len(self._thread_winners) > 8192:
                keys = sorted(self._thread_winners.keys(), key=lambda x: (x[0], x[1]))
                keep_keys = keys[-4096:]
                keep = {k: self._thread_winners[k] for k in keep_keys}
                self._thread_winners.clear()
                self._thread_winners.update(keep)

        except Exception:
            pass

    def _insert_candidate(self, cand: dict) -> bool:
        """
        Insert candidate into best-by-nonce table.

        Returns True if accepted/replaced.
        """
        nonce_u32 = int(cand["nonce_u32"]) & 0xFFFFFFFF

        prior = self._best_by_nonce.get(nonce_u32)
        if prior is None:
            self._best_by_nonce[nonce_u32] = cand
            self._accepted += 1
            self._mark_dirty()

            kept = len(self._best_by_nonce)
            if kept in (2, 4, 8, 16, 32, 64):
                self._global_evt_emit(
                    "burst",
                    details=(
                        f"owner={self.owner_key} job={self._job_id} "
                        f"gen={self._generation} unique_nonce_winners={kept}"
                    ),
                )

            self._track_thread_winner(cand)
            return True

        if self._is_better(cand, prior):
            self._best_by_nonce[nonce_u32] = cand
            self._replaced += 1
            self._mark_dirty()

            if self._replaced in (1, 3, 8):
                self._global_evt_emit(
                    "replace",
                    details=(
                        f"owner={self.owner_key} job={self._job_id} "
                        f"gen={self._generation} replaced={self._replaced}"
                    ),
                )

            self._track_thread_winner(cand)
            return True

        self._rejected_same_or_worse += 1
        self._track_thread_winner(cand)
        return False

    def _bounded_best(self, winners: list[dict], keep: int) -> list[dict]:
        keep = max(1, int(keep))

        if len(winners) <= keep:
            out = list(winners)
            out.sort(key=self._sort_key_dict)
            return out

        heap: list[tuple[tuple[int, int], dict]] = []
        push = heapq.heappush
        replace = heapq.heapreplace

        for cand in winners:
            nonce_u32 = int(cand["nonce_u32"])
            tail64 = int(cand["tail64"])

            entry = (self._heap_key(nonce_u32, tail64), cand)

            if len(heap) < keep:
                push(heap, entry)
            elif entry[0] > heap[0][0]:
                replace(heap, entry)

        out = [cand for _, cand in heap]
        out.sort(key=self._sort_key_dict)
        return out

    def _round_robin_winners(
        self,
        winners: list[dict],
        *,
        keep: int,
        threads: int,
    ) -> list[dict]:
        """
        Export unique nonce winners in source-thread round-robin order.

        Lower tail64 is better.
        """
        keep = max(1, int(keep))
        threads = max(1, int(threads))

        self._source_thread_counts = {}
        self._assigned_thread_counts = {}
        self._duplicate_candidate_count = 0
        self._duplicate_tail64_count = 0

        if not winners:
            return []

        queues: dict[int, list[dict]] = {}
        seen_identity: set[tuple[int, str]] = set()
        seen_tail64: set[tuple[int, int]] = set()

        for cand in winners:
            try:
                nonce_u32 = int(cand["nonce_u32"]) & 0xFFFFFFFF
                hash_hex = str(cand["hash_hex"])
                tail64 = int(cand["tail64"]) & 0xFFFFFFFFFFFFFFFF
                gen = int(cand.get("_generation", self._generation) or self._generation)
            except Exception:
                self._bad += 1
                continue

            identity = (nonce_u32, hash_hex)
            if identity in seen_identity:
                self._duplicate_candidate_count += 1
                continue
            seen_identity.add(identity)

            tail_key = (gen, tail64)
            if tail_key in seen_tail64:
                self._duplicate_tail64_count += 1
            else:
                seen_tail64.add(tail_key)

            source_thread = self._candidate_source_thread(cand, threads)
            queues.setdefault(source_thread, []).append(cand)
            self._source_thread_counts[source_thread] = (
                self._source_thread_counts.get(source_thread, 0) + 1
            )

        for q in queues.values():
            q.sort(key=self._sort_key_dict)

        source_order = sorted(
            queues.keys(),
            key=lambda tid: (
                self._sort_key_dict(queues[tid][0])
                if queues.get(tid)
                else (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF),
                tid,
            ),
        )

        out: list[dict] = []
        made_progress = True
        guard = 0

        while made_progress and len(out) < keep:
            made_progress = False

            for source_thread in source_order:
                q = queues.get(source_thread)
                if not q:
                    continue

                cand = q.pop(0)
                assigned_thread = len(out) % threads
                cand["_assigned_submit_thread"] = assigned_thread

                out.append(cand)
                self._assigned_thread_counts[assigned_thread] = (
                    self._assigned_thread_counts.get(assigned_thread, 0) + 1
                )

                made_progress = True

                if len(out) >= keep:
                    break

            guard += 1
            if guard > keep + threads + 4:
                break

        return out

    def _update_snapshot(self, exported: list[dict], threads: int) -> None:
        self._last_snapshot = {
            "owner": self.owner_key,
            "job_id": self._job_id,
            "generation": int(self._generation),
            "incoming": int(self._incoming),
            "accepted": int(self._accepted),
            "rejected_same_or_worse": int(self._rejected_same_or_worse),
            "replaced": int(self._replaced),
            "bad": int(self._bad),
            "merge_calls": int(self._merge_calls),
            "unique_nonce_winners": int(len(self._best_by_nonce)),
            "exported": int(len(exported or [])),
            "threads_inferred": int(threads),
            "source_thread_counts": {
                int(k): int(v) for k, v in self._source_thread_counts.items()
            },
            "assigned_thread_counts": {
                int(k): int(v) for k, v in self._assigned_thread_counts.items()
            },
            "duplicate_candidate_count": int(self._duplicate_candidate_count),
            "duplicate_tail64_count": int(self._duplicate_tail64_count),
            "thread_winners_tracked": int(len(self._thread_winners)),
        }

        for key, winner in list(self._thread_winners.items())[-32:]:
            try:
                gen, worker_id = key
                self._last_snapshot[f"worker_{int(worker_id)}_best_gen_{int(gen)}"] = {
                    "nonce": int(winner.get("nonce", 0)) & 0xFFFFFFFF,
                    "tail64": int(winner.get("tail64", 0)) & 0xFFFFFFFFFFFFFFFF,
                    "tail64_hex": f"0x{int(winner.get('tail64', 0)) & 0xFFFFFFFFFFFFFFFF:016X}",
                    "lane_id": int(winner.get("lane_id", 0)),
                    "generation": int(gen),
                    "worker_id": int(worker_id),
                }
            except Exception:
                pass

    def snapshot(self) -> dict:
        """
        Optional diagnostics. Does not affect the public API.
        """
        return dict(self._last_snapshot)

    def reset(
        self,
        *,
        job_id: str,
        generation: int,
        requested_keep: Optional[int] = None,
    ) -> None:
        self._job_id = str(job_id)
        self._generation = int(generation)
        self._requested_keep = max(1, int(requested_keep or self.max_keep_default))

        self._best_by_nonce.clear()

        self._incoming = 0
        self._accepted = 0
        self._rejected_same_or_worse = 0
        self._replaced = 0
        self._bad = 0
        self._merge_calls = 0

        self._dirty = True
        self._cached_keep = 0
        self._cached_out = []
        self._opened_logged = False
        self._last_export_sig = None

        self._thread_winners.clear()
        self._source_thread_counts = {}
        self._assigned_thread_counts = {}
        self._duplicate_candidate_count = 0
        self._duplicate_tail64_count = 0
        self._last_threads_inferred = 1

        self._last_snapshot = {
            "owner": self.owner_key,
            "job_id": self._job_id,
            "generation": int(self._generation),
            "incoming": 0,
            "accepted": 0,
            "rejected_same_or_worse": 0,
            "replaced": 0,
            "bad": 0,
            "merge_calls": 0,
            "unique_nonce_winners": 0,
            "exported": 0,
            "threads_inferred": 1,
            "source_thread_counts": {},
            "assigned_thread_counts": {},
            "duplicate_candidate_count": 0,
            "duplicate_tail64_count": 0,
            "thread_winners_tracked": 0,
        }

    def offer(
        self,
        *,
        nonce_u32: int,
        hash_hex: str,
        tail64: int,
    ) -> bool:
        raw = {
            "nonce_u32": nonce_u32,
            "hash_hex": hash_hex,
            "tail64": tail64,
            "_generation": int(self._generation),
        }

        if self._owner_thread_id >= 0:
            raw["_found_by_thread"] = int(self._owner_thread_id)
            raw["_lane_id"] = int(self._owner_thread_id)

        cand = self._normalize_candidate(raw)
        if cand is None:
            self._bad += 1
            return False

        self._incoming += 1

        if not self._opened_logged:
            self._opened_logged = True
            self._global_evt_emit(
                "batch_open",
                details=(
                    f"owner={self.owner_key} job={self._job_id} "
                    f"gen={self._generation} keep={self._requested_keep}"
                ),
            )

        return self._insert_candidate(cand)

    def offer_hit(
        self,
        *,
        nonce_u32: int,
        tail64: int,
        hash_hex: str,
    ) -> bool:
        return self.offer(
            nonce_u32=nonce_u32,
            hash_hex=hash_hex,
            tail64=tail64,
        )

    def merge_items(self, items: list[dict]) -> None:
        if not items:
            return

        self._merge_calls += 1
        changed = False

        for item in items:
            cand = self._normalize_candidate(item)
            if cand is None:
                self._bad += 1
                continue

            self._incoming += 1

            if self._insert_candidate(cand):
                changed = True

        if changed:
            self._mark_dirty()

        if self._merge_calls in (2, 4, 8, 16):
            self._global_evt_emit(
                "merge",
                details=(
                    f"owner={self.owner_key} job={self._job_id} "
                    f"gen={self._generation} merge_calls={self._merge_calls} "
                    f"unique_nonce_winners={len(self._best_by_nonce)}"
                ),
            )

    def merge_exported(self, items: list[dict]) -> None:
        self.merge_items(items)

    def export(self, max_results: Optional[int] = None) -> list[dict]:
        keep = max(1, int(max_results or self._requested_keep or self.max_keep_default))

        if not self._dirty and self._cached_keep == keep:
            return self._cached_out

        winners = list(self._best_by_nonce.values())

        if not winners:
            self._cached_keep = keep
            self._cached_out = []
            self._dirty = False
            self._update_snapshot([], 1)
            return self._cached_out

        threads = self._infer_thread_count(winners)
        self._last_threads_inferred = int(threads)

        # Keep a wider pool briefly so round-robin has enough candidates to
        # spread by worker/lane, then trim to requested keep.
        pre_keep = max(keep, min(len(winners), keep * max(1, min(threads, 16))))
        best_pre = self._bounded_best(winners, pre_keep)

        if threads > 1 and len(best_pre) > 1:
            out = self._round_robin_winners(
                best_pre,
                keep=keep,
                threads=threads,
            )

            self._global_evt_emit(
                "round_robin",
                details=(
                    f"owner={self.owner_key} job={self._job_id} "
                    f"gen={self._generation} threads={threads} "
                    f"exported={len(out)} source_threads={self._source_thread_counts} "
                    f"assigned_threads={self._assigned_thread_counts}"
                ),
            )
        else:
            out = self._bounded_best(winners, keep)
            self._source_thread_counts = {}
            self._assigned_thread_counts = {0: len(out)} if out else {}
            self._duplicate_candidate_count = 0
            self._duplicate_tail64_count = 0

        trimmed = max(0, len(winners) - len(out))

        # Return candidates with metadata preserved.
        #
        # JITWorker/CandidateSelector can use:
        #   _found_by_thread
        #   _generation
        #   _lane_id
        #   _assigned_submit_thread
        #
        # Strip these only at the final submit boundary if your submitter
        # requires the old 4-field shape.
        exported: list[dict] = []
        for cand in out:
            try:
                exported.append(dict(cand))
            except Exception:
                self._bad += 1

        self._cached_keep = keep
        self._cached_out = exported
        self._dirty = False

        self._update_snapshot(exported, threads)

        if self._bad > 0:
            self._global_evt_emit(
                "bad",
                details=(
                    f"owner={self.owner_key} job={self._job_id} "
                    f"gen={self._generation} bad={self._bad}"
                ),
            )

        if trimmed > 0:
            self._global_evt_emit(
                "trim",
                details=(
                    f"owner={self.owner_key} job={self._job_id} "
                    f"gen={self._generation} trimmed={trimmed} "
                    f"kept={len(exported)} requested={keep}"
                ),
            )

        if exported:
            best = min(exported, key=self._sort_key_dict)
            sig = (
                self._job_id,
                self._generation,
                self._incoming,
                self._accepted,
                self._rejected_same_or_worse,
                self._replaced,
                self._bad,
                self._merge_calls,
                len(exported),
                trimmed,
                int(best["nonce_u32"]),
                int(best["tail64"]),
                tuple(sorted(self._assigned_thread_counts.items())),
            )

            if sig != self._last_export_sig:
                self._last_export_sig = sig
                self._global_evt_emit(
                    "flush",
                    details=(
                        f"owner={self.owner_key} job={self._job_id} "
                        f"gen={self._generation} incoming={self._incoming} "
                        f"accepted={self._accepted} rejected={self._rejected_same_or_worse} "
                        f"replaced={self._replaced} merges={self._merge_calls} "
                        f"exported={len(exported)} best_nonce={int(best['nonce_u32'])} "
                        f"best_tail64={int(best['tail64'])} "
                        f"assigned_threads={self._assigned_thread_counts}"
                    ),
                )

        return exported

class _NonceLease(_ClassEventLogMixin):
    """
    Generic nonce ownership record.

    Performance goals:
    - safe to reuse outside JITWorker
    - no per-hash locking requirement
    - cheap range refresh for coordinator/frontier style ownership

    Notes:
    - use begin(...) when a new logical lease/job starts
    - use refresh_range(...) when the same owner/job simply moves to a new window
    - callers that need speed should snapshot once, then use local ints
    """

    def __init__(
        self,
        *,
        worker_index: Optional[int] = None,
        owner_key: Optional[str] = None,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.worker_index = None if worker_index is None else int(worker_index)
        self.owner_key = (
            str(owner_key)
            if owner_key is not None
            else (f"worker-{self.worker_index}" if self.worker_index is not None else "lease")
        )

        self._mu = threading.RLock()

        self._lease_id: int = 0
        self._job_id: str = ""
        self._generation: int = 0

        self._start_nonce: int = 0
        self._count: int = 0
        self._stop_nonce_exclusive: int = 0

        self._assigned_at: float = 0.0
        self._last_touch_at: float = 0.0
        self._done_hashes: int = 0

        self._evt_init(
            class_prefix="NonceLease",
            logger=logger,
            cooldowns={
                "begin": 45.0,
                "refresh": 60.0,
                "clear": 75.0,
                "slow_lane": 90.0,
            },
            phrases={
                "begin": [
                    "fresh lease took hold",
                    "a new nonce lane came online",
                    "lease woke up on live work",
                    "a new lease snapped into place",
                ],
                "refresh": [
                    "lease window slid forward",
                    "nonce lane refreshed",
                    "lease rearmed cleanly",
                    "lease advanced onto the next slice",
                ],
                "clear": [
                    "lease cooled off",
                    "nonce lane went quiet",
                    "lease stood down",
                    "lease cleared back to idle",
                ],
                "slow_lane": [
                    "lease has been quiet for a while",
                    "lease state is aging without much movement",
                    "nonce lease is stretching its legs slowly",
                    "this lease has lingered longer than usual",
                ],
            },
        )

    @staticmethod
    def _u32(v: int) -> int:
        return int(v) & 0xFFFFFFFF

    def _next_lease_id_locked(self) -> int:
        nxt = (self._lease_id + 1) & 0x7FFFFFFF
        if nxt == 0:
            nxt = 1
        return nxt

    def begin(
        self,
        *,
        job_id: str,
        generation: int,
        start_nonce: int,
        count: int,
        force_log: bool = False,
    ) -> int:
        """
        Start a new logical lease. This bumps lease_id.
        Use this on a new job or when you need a brand new ownership epoch.
        """
        job_id = str(job_id)
        generation = int(generation)
        start_nonce = self._u32(start_nonce)
        count = max(0, int(count))

        with self._mu:
            self._lease_id = self._next_lease_id_locked()
            self._job_id = job_id
            self._generation = generation
            self._start_nonce = start_nonce
            self._count = count
            self._stop_nonce_exclusive = self._u32(start_nonce + count)

            now = time.perf_counter()
            self._assigned_at = now
            self._last_touch_at = now
            self._done_hashes = 0

            if count > 0:
                self._evt_emit(
                    "begin",
                    details=(
                        f"owner={self.owner_key} lease_id={self._lease_id} "
                        f"job={job_id} gen={generation} start={start_nonce} count={count}"
                    ),
                    force=force_log,
                )

            return self._lease_id

    def refresh_range(
        self,
        *,
        start_nonce: int,
        count: int,
        emit_log: bool = False,
    ) -> None:
        """
        Move the active range forward without changing lease_id/job/generation.
        This is the low-overhead path for a coordinator/frontier owner.
        """
        start_nonce = self._u32(start_nonce)
        count = max(0, int(count))

        with self._mu:
            self._start_nonce = start_nonce
            self._count = count
            self._stop_nonce_exclusive = self._u32(start_nonce + count)
            self._last_touch_at = time.perf_counter()

            if emit_log and count > 0:
                self._evt_emit(
                    "refresh",
                    details=(
                        f"owner={self.owner_key} lease_id={self._lease_id} "
                        f"job={self._job_id} gen={self._generation} "
                        f"start={start_nonce} count={count}"
                    ),
                )

    def clear(self) -> None:
        with self._mu:
            had_work = bool(self._job_id) or self._count > 0
            old_job = self._job_id
            old_generation = self._generation

            self._job_id = ""
            self._generation = 0
            self._start_nonce = 0
            self._count = 0
            self._stop_nonce_exclusive = 0
            self._assigned_at = 0.0
            self._last_touch_at = 0.0
            self._done_hashes = 0

            if had_work:
                self._evt_emit(
                    "clear",
                    details=(
                        f"owner={self.owner_key} last_job={old_job} "
                        f"last_gen={old_generation}"
                    ),
                )

    def matches(self, *, lease_id: int, job_id: str, generation: int) -> bool:
        with self._mu:
            return (
                self._lease_id == int(lease_id)
                and self._job_id == str(job_id)
                and self._generation == int(generation)
                and self._count > 0
            )

    def nonce_at(self, offset: int) -> int:
        offset = max(0, int(offset))
        with self._mu:
            return self._u32(self._start_nonce + offset)

    def note_progress(self, done_hashes: int) -> None:
        with self._mu:
            self._done_hashes = max(0, int(done_hashes))
            self._last_touch_at = time.perf_counter()

            if self._assigned_at > 0.0:
                age_ms = max(0.0, (time.perf_counter() - self._assigned_at) * 1000.0)
                if age_ms >= 12000.0 and self._done_hashes <= 0 and self._count > 0:
                    self._evt_emit(
                        "slow_lane",
                        details=(
                            f"owner={self.owner_key} lease_id={self._lease_id} "
                            f"job={self._job_id} gen={self._generation} age_ms={age_ms:.0f}"
                        ),
                    )

    def progress(self) -> int:
        with self._mu:
            return self._done_hashes

    def age_ms(self) -> float:
        with self._mu:
            if self._assigned_at <= 0.0:
                return 0.0
            return max(0.0, (time.perf_counter() - self._assigned_at) * 1000.0)

    def snapshot(self) -> tuple[int, str, int, int, int]:
        with self._mu:
            return (
                self._lease_id,
                self._job_id,
                self._generation,
                self._start_nonce,
                self._count,
            )

    def snapshot_dict(self) -> dict:
        with self._mu:
            return {
                "owner_key": self.owner_key,
                "worker_index": self.worker_index,
                "lease_id": self._lease_id,
                "job_id": self._job_id,
                "generation": self._generation,
                "start_nonce": self._start_nonce,
                "count": self._count,
                "stop_nonce_exclusive": self._stop_nonce_exclusive,
                "done_hashes": self._done_hashes,
                "age_ms": self.age_ms(),
            }


class _JobDispatchCoordinator(_ClassEventLogMixin):
    """
    Self-contained coordinator backed by one reusable NonceLease.

    Hashrate safety:
    - this class is not in the RandomX hot loop
    - it uses one lease only for ownership/frontier state
    - same-job reservations refresh the range without bumping lease_id
    """

    def __init__(
        self,
        *,
        hashed_job_start: bool = True,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._mu = threading.RLock()

        self._active_job_id: Optional[str] = None
        self._active_generation: int = 0
        self._job_started_at: float = 0.0
        self._next_nonce: int = 0

        self._hashed_job_start = bool(hashed_job_start)
        self.logger = logger or (lambda s: None)

        self._dispatch_seq: int = 0
        self._last_reserved_start: int = 0
        self._last_reserved_count: int = 0

        # one reusable lease for the coordinator itself
        self._active_lease = _NonceLease(
            owner_key="dispatch",
            logger=self.logger,
        )

        self._evt_init(
            class_prefix="JobDispatchCoordinator",
            logger=logger,
            cooldowns={
                "job_start": 35.0,
                "jump": 60.0,
                "overlap": 60.0,
                "backward": 75.0,
                "wrap": 90.0,
            },
            phrases={
                "job_start": [
                    "fresh work rolled in",
                    "dispatch picked up a new lane",
                    "a new mining wave landed",
                    "the board changed under dispatch",
                ],
                "jump": [
                    "nonce lane vaulted ahead",
                    "dispatch skipped into a later slice",
                    "window hopped forward cleanly",
                    "the nonce stream lunged ahead",
                ],
                "overlap": [
                    "dispatch untangled a crossing nonce lane",
                    "an overlap surfaced and got smoothed out",
                    "two nonce paths brushed together and were separated",
                    "dispatch nudged a colliding lane ahead",
                ],
                "backward": [
                    "an older nonce request tried to come back",
                    "dispatch caught stale backward motion",
                    "a rewind attempt got turned forward",
                    "dispatch refused to reopen an older lane",
                ],
                "wrap": [
                    "nonce space wrapped around",
                    "the nonce ring crossed its boundary",
                    "dispatch rolled through the uint32 seam",
                    "the reservation looped across the edge",
                ],
            },
        )

    def _log(self, text: str) -> None:
        try:
            self.logger(text)
        except Exception:
            pass

    @staticmethod
    def _norm_job_id(job_id: str) -> str:
        return str(job_id)

    @staticmethod
    def _u32(v: int) -> int:
        return int(v) & 0xFFFFFFFF

    @staticmethod
    def _forward_distance(cur: int, req: int) -> int:
        return (int(req) - int(cur)) & 0xFFFFFFFF

    @staticmethod
    def _backward_distance(cur: int, req: int) -> int:
        return (int(cur) - int(req)) & 0xFFFFFFFF

    @staticmethod
    def _is_forward_or_equal(req: int, cur: int) -> bool:
        delta = (int(req) - int(cur)) & 0xFFFFFFFF
        return delta == 0 or delta < 0x80000000

    def _next_generation_locked(self) -> int:
        nxt = (self._active_generation + 1) & 0x7FFFFFFF
        if nxt == 0:
            nxt = 1
        return nxt

    def _seed_nonce_for_job(self, job_id: str, generation: int) -> int:
        if not self._hashed_job_start:
            return 0

        h = hashlib.blake2s(
            f"{self._norm_job_id(job_id)}|{int(generation)}".encode("utf-8", "ignore"),
            digest_size=4,
        ).digest()
        return int.from_bytes(h, "little", signed=False) & 0xFFFFFFFF

    def _initial_nonce_for_job(self, job_id: str, generation: int) -> int:
        return self._seed_nonce_for_job(job_id, generation) & 0xFFFFFFC0

    def _reserve_locked(self, start_nonce: int, count: int) -> tuple[int, bool]:
        start_nonce = self._u32(start_nonce)
        count = max(1, int(count))

        stop = (start_nonce + count) & 0xFFFFFFFF
        wrapped = stop < start_nonce or (count > 0 and stop == start_nonce)

        self._next_nonce = stop
        self._last_reserved_start = start_nonce
        self._last_reserved_count = count
        self._dispatch_seq += 1

        return start_nonce, wrapped

    def observe_and_reserve(
        self,
        job_id: str,
        requested_start_nonce: int,
        count: int,
    ) -> tuple[int, int]:
        job_id = self._norm_job_id(job_id)
        count = max(1, int(count))
        req = self._u32(requested_start_nonce)

        with self._mu:
            previous_age_ms = 0.0
            if self._job_started_at > 0.0:
                previous_age_ms = max(
                    0.0,
                    (time.perf_counter() - self._job_started_at) * 1000.0,
                )

            is_new_job = (self._active_job_id != job_id)

            if is_new_job:
                self._active_job_id = job_id
                self._active_generation = self._next_generation_locked()
                self._job_started_at = time.perf_counter()

                actual_start = req if req != 0 else self._initial_nonce_for_job(job_id, self._active_generation)

                # new logical ownership epoch
                self._active_lease.begin(
                    job_id=job_id,
                    generation=self._active_generation,
                    start_nonce=actual_start,
                    count=count,
                )

                actual_start, wrapped = self._reserve_locked(actual_start, count)

                self._evt_emit(
                    "job_start",
                    details=(
                        f"job={job_id} gen={self._active_generation} "
                        f"start={actual_start} count={count} previous_age_ms={previous_age_ms:.0f}"
                    ),
                )

                if wrapped:
                    self._evt_emit(
                        "wrap",
                        details=(
                            f"job={job_id} gen={self._active_generation} "
                            f"start={actual_start} count={count}"
                        ),
                    )

                return actual_start, self._active_generation

            expected = self._next_nonce

            if req == expected:
                actual_start = req

            elif self._is_forward_or_equal(req, expected):
                gap = self._forward_distance(expected, req)
                actual_start = req

                if gap >= max(2048, count * 8):
                    self._evt_emit(
                        "jump",
                        details=(
                            f"job={job_id} gen={self._active_generation} "
                            f"expected={expected} requested={req} gap={gap}"
                        ),
                    )
            else:
                actual_start = expected
                overlap_span = self._forward_distance(req, expected)

                if overlap_span <= 0x00FFFFFF:
                    self._evt_emit(
                        "overlap",
                        details=(
                            f"job={job_id} gen={self._active_generation} "
                            f"requested={req} repaired={actual_start}"
                        ),
                    )
                else:
                    self._evt_emit(
                        "backward",
                        details=(
                            f"job={job_id} gen={self._active_generation} "
                            f"requested={req} repaired={actual_start}"
                        ),
                    )

            actual_start, wrapped = self._reserve_locked(actual_start, count)

            # same logical lease, just a new reservation window
            self._active_lease.refresh_range(
                start_nonce=actual_start,
                count=count,
                emit_log=False,
            )

            if wrapped:
                self._evt_emit(
                    "wrap",
                    details=(
                        f"job={job_id} gen={self._active_generation} "
                        f"start={actual_start} count={count}"
                    ),
                )

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

    def current_lease_snapshot(self) -> dict:
        return self._active_lease.snapshot_dict()

    def clear(self) -> None:
        with self._mu:
            self._active_job_id = None
            self._active_generation = 0
            self._job_started_at = 0.0
            self._next_nonce = 0
            self._last_reserved_start = 0
            self._last_reserved_count = 0
            self._dispatch_seq = 0
            self._active_lease.clear()

    def snapshot(self) -> dict:
        with self._mu:
            return {
                "active_job_id": self._active_job_id,
                "active_generation": self._active_generation,
                "job_age_ms": self.current_job_age_ms(),
                "next_nonce": self._next_nonce,
                "last_reserved_start": self._last_reserved_start,
                "last_reserved_count": self._last_reserved_count,
                "dispatch_seq": self._dispatch_seq,
                "lease": self._active_lease.snapshot_dict(),
            }


class _CandidateSelector(_ClassEventLogMixin):
    """
    High-throughput candidate selector.

    Design goals:
    - keep the public API identical
    - minimize allocations and full-list sorting
    - collapse repeated nonces to the strongest candidate
    - avoid redundant ranking math
    - preserve logging through the mixin
    - preserve worker/lane metadata internally
    - order winners round-robin by source thread/lane
    - return clean candidate dicts with debug fields stripped

    Expected candidate input fields:
        nonce_u32
        hash_hex
        tail64 optional
        share_diff_est optional

    Optional debug metadata preserved internally:
        _found_by_thread
        _worker_index
        _thread_id
        _generation
        _lane_id
        _assigned_submit_thread
    """

    def __init__(
        self,
        *,
        max_keep_default: int = 16,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.max_keep_default = max(1, int(max_keep_default))

        self._last_snapshot: dict = {
            "incoming": 0,
            "kept": 0,
            "exact_duplicates_removed": 0,
            "same_nonce_reduced": 0,
            "bad_candidates": 0,
            "unique_nonce_winners": 0,
            "threads_inferred": 1,
            "round_robin_enabled": False,
            "source_thread_counts": {},
            "assigned_thread_counts": {},
            "best_nonce": 0,
            "best_tail64": 0,
            "best_share_diff": 0.0,
        }

        self._evt_init(
            class_prefix="CandidateSelector",
            logger=logger,
            cooldowns={
                "kept_candidates": 75.0,
                "dedup": 90.0,
                "nonce_collapse": 90.0,
                "round_robin": 75.0,
                "bad": 90.0,
            },
            phrases={
                "kept_candidates": [
                    "strong candidates floated to the surface",
                    "a promising set survived ranking",
                    "the ranking pass held onto live contenders",
                    "candidate sorting kept the sharpest edges",
                ],
                "dedup": [
                    "duplicates got brushed out of the pile",
                    "ranking shaved off repeated candidates",
                    "the selector thinned out mirrored results",
                    "duplicate candidate echoes were removed",
                ],
                "nonce_collapse": [
                    "multiple hits on the same nonce were narrowed down",
                    "the selector kept only the sharpest nonce echoes",
                    "weaker results on repeated nonces were set aside",
                    "nonce collisions were reduced to their strongest form",
                ],
                "round_robin": [
                    "unique nonce winners were spread across worker lanes",
                    "candidate winners were balanced by source thread",
                    "the selector interleaved winners for parallel submission",
                    "ranked candidates were distributed across active lanes",
                ],
                "bad": [
                    "some malformed candidates were ignored",
                    "the selector stepped around damaged entries",
                    "broken candidate records were filtered out",
                    "invalid candidate shapes were discarded",
                ],
            },
        )

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

    @staticmethod
    def _normalize(raw: dict) -> Optional[dict]:
        """
        Normalize a candidate while preserving internal debug metadata.

        Important:
            Lower tail64 is better.
        """
        try:
            if raw is None:
                return None

            nonce_u32 = int(raw.get("nonce_u32", 0)) & 0xFFFFFFFF
            hash_hex = str(raw.get("hash_hex", "") or "").strip().lower()
            if not hash_hex:
                return None

            tail64 = raw.get("tail64", None)
            if tail64 is None:
                tail64 = raw.get("_tail64", None)
            if tail64 is None:
                tail64 = _CandidateSelector._tail64_from_hash_hex(hash_hex)
            tail64 = int(tail64) & 0xFFFFFFFFFFFFFFFF

            share_diff_est = raw.get("share_diff_est", None)
            if share_diff_est is None:
                share_diff_est = _CandidateSelector._share_diff_est(tail64)
            share_diff_est = float(share_diff_est)

            out = {
                "nonce_u32": nonce_u32,
                "hash_hex": hash_hex,
                "tail64": tail64,
                "share_diff_est": share_diff_est,
            }

            # Preserve debug/internal metadata for ranking and round-robin ordering.
            # These are stripped before rank() returns.
            for key in (
                "_found_by_thread",
                "_worker_index",
                "_thread_id",
                "_generation",
                "_lane_id",
                "_assigned_submit_thread",
                "_tail64",
                "_nonce",
                "worker_index",
                "thread_id",
                "lane_id",
                "generation",
            ):
                if key in raw:
                    out[key] = raw.get(key)

            if "_tail64" not in out:
                out["_tail64"] = tail64
            if "_nonce" not in out:
                out["_nonce"] = nonce_u32

            return out
        except Exception:
            return None

    @staticmethod
    def _is_better(a: dict, b: dict) -> bool:
        """
        Lower tail64 is better.
        Lower nonce is the stable tie-break.
        """
        at = int(a["tail64"])
        bt = int(b["tail64"])
        if at != bt:
            return at < bt
        return int(a["nonce_u32"]) < int(b["nonce_u32"])

    @staticmethod
    def _sort_key(x: dict) -> tuple[int, int]:
        return (
            int(x["tail64"]),
            int(x["nonce_u32"]),
        )

    @staticmethod
    def _heap_key(x: dict) -> tuple[int, int]:
        """
        Heap stores the current worst kept entry at index 0.
        More positive is better for replacement testing.
        """
        return (
            -int(x["tail64"]),
            -int(x["nonce_u32"]),
        )

    @staticmethod
    def _clean_candidate(c: dict) -> dict:
        """
        Strip debug fields before returning candidates to caller/submission path.
        """
        return {
            "nonce_u32": int(c["nonce_u32"]) & 0xFFFFFFFF,
            "hash_hex": str(c["hash_hex"]),
            "tail64": int(c["tail64"]) & 0xFFFFFFFFFFFFFFFF,
            "share_diff_est": float(c["share_diff_est"]),
        }

    @staticmethod
    def _read_env_threads(default: int = 1) -> int:
        try:
            import os

            for name in (
                "JITWORKER_SELECTOR_THREADS",
                "MONERO_SELECTOR_THREADS",
                "JITWORKER_THREADS",
                "MONERO_THREADS",
            ):
                raw = os.getenv(name)
                if raw is None:
                    continue

                try:
                    value = int(str(raw).strip())
                    if value > 0:
                        return value
                except Exception:
                    continue
        except Exception:
            pass

        return max(1, int(default))

    @staticmethod
    def _safe_int(value, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return int(default)

    def _candidate_source_thread(self, cand: dict, threads: int) -> int:
        """
        Infer the source worker/thread for round-robin ordering.

        Preferred metadata:
            _found_by_thread
            _worker_index
            _thread_id
            worker_index
            thread_id
            _lane_id
            lane_id

        Fallback:
            nonce % threads
        """
        threads = max(1, int(threads))

        for key in (
            "_found_by_thread",
            "_worker_index",
            "_thread_id",
            "worker_index",
            "thread_id",
            "_lane_id",
            "lane_id",
        ):
            if key not in cand:
                continue

            try:
                value = int(cand.get(key))
                if value >= 0:
                    return value % threads
            except Exception:
                continue

        try:
            return int(cand["nonce_u32"]) % threads
        except Exception:
            return 0

    def _infer_thread_count(self, candidates: list[dict]) -> int:
        """
        Infer active thread count from preserved metadata.

        If no metadata exists, uses env fallback. If no env exists, returns 1.
        """
        max_seen = -1

        for cand in candidates or []:
            for key in (
                "_found_by_thread",
                "_worker_index",
                "_thread_id",
                "worker_index",
                "thread_id",
                "_lane_id",
                "lane_id",
            ):
                if key not in cand:
                    continue

                try:
                    value = int(cand.get(key))
                    if value >= 0:
                        max_seen = max(max_seen, value)
                except Exception:
                    pass

        if max_seen >= 0:
            return max(1, max_seen + 1)

        return self._read_env_threads(default=1)

    def _bounded_best(self, winners: list[dict], keep: int) -> list[dict]:
        """
        Keep the best K winners.

        For small candidate sets, direct sort is faster and simpler.
        For larger sets, use bounded heap.
        """
        keep = max(1, int(keep))

        if len(winners) <= keep:
            out = list(winners)
            out.sort(key=self._sort_key)
            return out

        heap: list[tuple[tuple[int, int], dict]] = []

        for cand in winners:
            entry = (self._heap_key(cand), cand)

            if len(heap) < keep:
                heapq.heappush(heap, entry)
                continue

            if entry[0] > heap[0][0]:
                heapq.heapreplace(heap, entry)

        out = [cand for _, cand in heap]
        out.sort(key=self._sort_key)
        return out

    def _round_robin_winners(
        self,
        winners: list[dict],
        *,
        keep: int,
        threads: int,
    ) -> tuple[list[dict], dict[int, int], dict[int, int]]:
        """
        Thread-aware winner distribution.

        Input must already be deduped by nonce.

        Lower tail64 is better. Each source thread/lane queue is sorted by quality,
        then the result is interleaved one candidate per thread per round.

        Returns:
            ordered candidates with debug metadata still attached
            source_thread_counts
            assigned_thread_counts
        """
        keep = max(1, int(keep))
        threads = max(1, int(threads))

        if not winners:
            return [], {}, {}

        queues: dict[int, list[dict]] = {}
        source_counts: dict[int, int] = {}

        for cand in winners:
            source_thread = self._candidate_source_thread(cand, threads)
            queues.setdefault(source_thread, []).append(cand)
            source_counts[source_thread] = source_counts.get(source_thread, 0) + 1

        for q in queues.values():
            q.sort(key=self._sort_key)

        # Start with the source thread whose best candidate is strongest.
        source_order = sorted(
            queues.keys(),
            key=lambda tid: (
                self._sort_key(queues[tid][0]) if queues.get(tid) else (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF),
                tid,
            ),
        )

        out: list[dict] = []
        assigned_counts: dict[int, int] = {}

        made_progress = True
        round_index = 0

        while made_progress and len(out) < keep:
            made_progress = False

            for source_thread in source_order:
                q = queues.get(source_thread)
                if not q:
                    continue

                cand = q.pop(0)
                assigned_thread = len(out) % threads

                cand["_assigned_submit_thread"] = assigned_thread
                out.append(cand)

                assigned_counts[assigned_thread] = assigned_counts.get(assigned_thread, 0) + 1
                made_progress = True

                if len(out) >= keep:
                    break

            round_index += 1
            if round_index > keep + threads + 4:
                break

        return out, source_counts, assigned_counts

    def _update_snapshot(
        self,
        *,
        incoming: int,
        kept: int,
        exact_dupes: int,
        bad_items: int,
        weaker_same_nonce: int,
        unique_nonce_winners: int,
        threads: int,
        round_robin_enabled: bool,
        source_thread_counts: dict[int, int],
        assigned_thread_counts: dict[int, int],
        out: list[dict],
    ) -> None:
        best = out[0] if out else None

        self._last_snapshot = {
            "incoming": int(incoming),
            "kept": int(kept),
            "exact_duplicates_removed": int(exact_dupes),
            "same_nonce_reduced": int(weaker_same_nonce),
            "bad_candidates": int(bad_items),
            "unique_nonce_winners": int(unique_nonce_winners),
            "threads_inferred": int(threads),
            "round_robin_enabled": bool(round_robin_enabled),
            "source_thread_counts": {
                int(k): int(v) for k, v in (source_thread_counts or {}).items()
            },
            "assigned_thread_counts": {
                int(k): int(v) for k, v in (assigned_thread_counts or {}).items()
            },
            "best_nonce": 0 if best is None else int(best["nonce_u32"]),
            "best_tail64": 0 if best is None else int(best["tail64"]),
            "best_tail64_hex": "0x0000000000000000"
            if best is None
            else f"0x{int(best['tail64']) & 0xFFFFFFFFFFFFFFFF:016X}",
            "best_share_diff": 0.0 if best is None else float(best["share_diff_est"]),
        }

    def snapshot(self) -> dict:
        """
        Optional diagnostics. Does not affect the public rank() API.
        """
        return dict(self._last_snapshot)

    def rank(self, candidates: list[dict], max_results: int) -> list[dict]:
        keep = max(1, int(max_results or self.max_keep_default))

        exact_dupes = 0
        bad_items = 0
        weaker_same_nonce = 0

        # Pass 1:
        # - normalize candidates
        # - remove exact duplicates
        # - keep strongest candidate for each nonce
        seen_exact: set[tuple[int, str]] = set()
        best_by_nonce: dict[int, dict] = {}

        incoming_count = len(candidates or [])

        for raw in candidates or []:
            cand = self._normalize(raw)
            if cand is None:
                bad_items += 1
                continue

            nonce_u32 = int(cand["nonce_u32"])
            hash_hex = str(cand["hash_hex"])

            exact_key = (nonce_u32, hash_hex)
            if exact_key in seen_exact:
                exact_dupes += 1
                continue

            seen_exact.add(exact_key)

            prior = best_by_nonce.get(nonce_u32)
            if prior is None:
                best_by_nonce[nonce_u32] = cand
                continue

            if self._is_better(cand, prior):
                best_by_nonce[nonce_u32] = cand

            weaker_same_nonce += 1

        winners = list(best_by_nonce.values())
        threads = self._infer_thread_count(winners)

        # Keep more than requested briefly so round-robin has room to balance.
        # Final output is still limited to keep.
        pre_keep = max(keep, min(len(winners), keep * max(1, min(threads, 16))))

        best_pre = self._bounded_best(winners, pre_keep)

        round_robin_enabled = threads > 1 and len(best_pre) > 1

        if round_robin_enabled:
            ordered, source_thread_counts, assigned_thread_counts = self._round_robin_winners(
                best_pre,
                keep=keep,
                threads=threads,
            )
        else:
            ordered = self._bounded_best(winners, keep)
            source_thread_counts = {}
            assigned_thread_counts = {0: len(ordered)} if ordered else {}

        # Final quality sanity pass inside the selected set:
        # - still deduped by nonce
        # - already balanced by thread
        # - limited to keep
        ordered = ordered[:keep]

        out = [self._clean_candidate(c) for c in ordered]

        if exact_dupes > 0:
            self._evt_emit(
                "dedup",
                details=(
                    f"exact_duplicates_removed={exact_dupes} "
                    f"incoming={incoming_count}"
                ),
            )

        if weaker_same_nonce > 0:
            self._evt_emit(
                "nonce_collapse",
                details=(
                    f"same_nonce_reduced={weaker_same_nonce} "
                    f"unique_nonce_winners={len(best_by_nonce)}"
                ),
            )

        if round_robin_enabled:
            self._evt_emit(
                "round_robin",
                details=(
                    f"threads={threads} "
                    f"kept={len(out)} "
                    f"unique_nonce_winners={len(best_by_nonce)} "
                    f"source_threads={source_thread_counts} "
                    f"assigned_threads={assigned_thread_counts}"
                ),
            )

        if bad_items > 0:
            self._evt_emit(
                "bad",
                details=(
                    f"bad_candidates={bad_items} "
                    f"incoming={incoming_count}"
                ),
            )

        if out:
            best = out[0]
            self._evt_emit(
                "kept_candidates",
                details=(
                    f"kept={len(out)} requested={keep} "
                    f"best_nonce={int(best['nonce_u32'])} "
                    f"best_tail64={int(best['tail64'])} "
                    f"best_share_diff={float(best['share_diff_est']):,.2f}"
                ),
            )

        self._update_snapshot(
            incoming=incoming_count,
            kept=len(out),
            exact_dupes=exact_dupes,
            bad_items=bad_items,
            weaker_same_nonce=weaker_same_nonce,
            unique_nonce_winners=len(best_by_nonce),
            threads=threads,
            round_robin_enabled=round_robin_enabled,
            source_thread_counts=source_thread_counts,
            assigned_thread_counts=assigned_thread_counts,
            out=out,
        )

        return out

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


class _HybridExecutionController(_ClassEventLogMixin):
    """
    Ultra-safe controller for heavy-thread RandomX mining.
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
        self._max_thunk_lanes = 4
        self._active_invocations = 0
        self._active_native_invocations = 0

        self._started_at = time.perf_counter()
        self._native_startup_grace_until = self._started_at + 8.0

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

        self._evt_init(
            class_prefix="HybridExecutionController",
            logger=logger,
            cooldowns={
                "usage_promote": 90.0,
                "thunk_promote": 90.0,
                "usage_disabled": 180.0,
                "thunk_disabled": 180.0,
                "fallback": 90.0,
                "pressure": 120.0,
                "close": 120.0,
            },
            phrases={
                "usage_promote": [
                    "python_usage lane woke up",
                    "a worker climbed onto the usage path",
                    "usage execution took a turn at the wheel",
                    "the usage lane opened briefly",
                ],
                "thunk_promote": [
                    "a thunk lane came online",
                    "native thunk execution stepped in",
                    "one worker crossed onto the thunk path",
                    "the thunk lane flickered to life",
                ],
                "usage_disabled": [
                    "python_usage went dark for this run",
                    "the usage lane was shut down after a hard hit",
                    "usage execution bowed out",
                    "python_usage stood down for safety",
                ],
                "thunk_disabled": [
                    "the thunk lane went dark for this run",
                    "native thunk execution stood down",
                    "the thunk path bowed out after a hard hit",
                    "thunk execution was shelved for safety",
                ],
                "fallback": [
                    "execution drifted back to direct mode",
                    "the worker fell back onto the safe lane",
                    "direct execution took over again",
                    "the fast path folded back into direct work",
                ],
                "pressure": [
                    "native paths stayed quiet under load",
                    "pressure kept the fragile lanes asleep",
                    "runtime load held native execution back",
                    "the controller stayed conservative under pressure",
                ],
                "close": [
                    "execution lanes cooled off",
                    "the controller wound its lanes down",
                    "runtime execution stood down cleanly",
                    "the execution controller settled back to idle",
                ],
            },
        )

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
        return self.threads <= self._native_thread_cap_for_usage

    def _feature_available_locked(self, feature: str) -> bool:
        now = self._now()

        if now < self._native_startup_grace_until:
            return False

        if self._active_invocations > 1:
            self._evt_emit(
                "pressure",
                details=f"feature={feature} active_invocations={self._active_invocations}",
            )
            return False

        if self._active_native_invocations > 0:
            self._evt_emit(
                "pressure",
                details=f"feature={feature} active_native_invocations={self._active_native_invocations}",
            )
            return False

        if feature == "usage":
            if not self._usage_enabled or self._usage_permanently_disabled:
                return False
            if now < self._usage_disabled_until:
                return False
            if self.python_usage is None:
                return False
            if self.threads > self._native_thread_cap_for_usage:
                self._evt_emit(
                    "pressure",
                    details=f"feature=usage threads={self.threads} cap={self._native_thread_cap_for_usage}",
                )
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
                self._evt_emit(
                    "pressure",
                    details=f"feature=thunk threads={self.threads} cap={self._native_thread_cap_for_thunk}",
                )
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

            self._usage_permanently_disabled = True
            self._evt_emit(
                "usage_disabled",
                details=(
                    f"stage={stage} worker={lane.worker_index} "
                    f"av_count={self._usage_av_count} reason={reason}"
                ),
                force=True,
            )

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
            self._evt_emit(
                "thunk_disabled",
                details=(
                    f"stage={stage} worker={lane.worker_index} "
                    f"av_count={self._thunk_av_count} reason={reason}"
                ),
                force=True,
            )

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
        old_mode = lane.mode

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
        self._evt_emit(
            "fallback",
            details=f"worker={lane.worker_index} from={old_mode} reason={reason}",
        )

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
                self._evt_emit(
                    "usage_promote",
                    details=f"worker={st.worker_index}",
                )
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
                self._evt_emit(
                    "thunk_promote",
                    details=f"worker={st.worker_index}",
                )
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
            rc = int(st.callback(None))

            with self._mu:
                lane.last_ok = True
                lane.last_error = None
                lane.direct_successes += 1
                self._stats["direct_invoke_ok"] += 1

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

        self._evt_emit("close", details=f"threads={self.threads}", force=True)

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


class RandomXDatasetBuilder(_ClassEventLogMixin):
    """
    Centralizes RandomX seed changes so only one thread pays the full
    dataset/cache rebuild cost per seed.

    Patch behavior:
    - safe same-seed epoch batching/coalescing
    - generation/worker epoch history
    - no unsafe dataset reuse across different seed_hash values
    - optional hint warming when the caller has a real next seed hash
    - richer snapshot/debug stats

    Important:
        RandomX datasets are seed-bound. Never reuse an epoch for a different
        seed_hash. This class only batches repeated requests for the same seed.
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

        self._last_seed: bytes = b""
        self._last_epoch: int = 0
        self._same_seed_hits: int = 0

        # generation -> compact history
        self.epoch_history: dict[int, dict[str, Any]] = {}

        # seed_hex16 -> compact history
        self._seed_epoch_history: dict[str, dict[str, Any]] = {}

        self._stats = {
            "build_requests": 0,
            "build_starts": 0,
            "build_waits": 0,
            "build_success": 0,
            "build_fail": 0,
            "same_seed_fast_path": 0,
            "epoch_batch_hits": 0,
            "hint_warm_calls": 0,
            "hint_warm_success": 0,
            "history_updates": 0,
        }

        self._evt_init(
            class_prefix="RandomXDatasetBuilder",
            logger=logger,
            cooldowns={
                "build_start": 60.0,
                "build_wait": 75.0,
                "build_done": 60.0,
                "build_fail": 90.0,
                "epoch_batch": 75.0,
                "hint_warm": 90.0,
            },
            phrases={
                "build_start": [
                    "a fresh dataset build began",
                    "seed preparation just took the floor",
                    "RandomX dataset work spun up",
                    "a new seed build woke up",
                ],
                "build_wait": [
                    "another thread is already tending this seed",
                    "seed preparation is already in flight",
                    "the dataset lane is busy with this seed",
                    "build work is already underway for this seed",
                ],
                "build_done": [
                    "dataset preparation settled into place",
                    "the seed build landed cleanly",
                    "RandomX dataset work came together",
                    "the fresh dataset is ready to breathe",
                ],
                "build_fail": [
                    "dataset preparation hit a wall",
                    "the seed build stumbled hard",
                    "RandomX dataset work fell out of step",
                    "the current build attempt broke apart",
                ],
                "epoch_batch": [
                    "same-seed epoch requests were coalesced",
                    "dataset reuse stayed safely inside the same seed",
                    "repeated seed work was collapsed into one ready epoch",
                    "epoch batching avoided redundant seed preparation",
                ],
                "hint_warm": [
                    "a hinted seed was warmed ahead of use",
                    "the dataset builder accepted a real next-seed hint",
                    "a seed hint was prepared synchronously",
                    "the next known seed was brought into readiness",
                ],
            },
        )

    def _log(self, msg: str) -> None:
        try:
            self.logger(msg)
        except Exception:
            pass

    @staticmethod
    def _seed_key(seed_hash: bytes) -> str:
        return bytes(seed_hash or b"").hex()[:16]

    def _trim_history_locked(self) -> None:
        if len(self.epoch_history) > 256:
            keys = sorted(self.epoch_history.keys())[-128:]
            self.epoch_history = {k: self.epoch_history[k] for k in keys}

        if len(self._seed_epoch_history) > 256:
            items = sorted(
                self._seed_epoch_history.items(),
                key=lambda kv: int(kv[1].get("last_epoch", 0)),
            )[-128:]
            self._seed_epoch_history = dict(items)

    def _note_epoch_history_locked(
        self,
        *,
        seed_hash: bytes,
        epoch: int,
        generation: Optional[int] = None,
        worker_index: Optional[int] = None,
        source: str = "ensure",
    ) -> None:
        seed_hash = bytes(seed_hash or b"")
        seed_key = self._seed_key(seed_hash)
        epoch = int(epoch)

        self._stats["history_updates"] += 1

        if generation is not None:
            gen = int(generation)
            hist = self.epoch_history.setdefault(
                gen,
                {
                    "generation": gen,
                    "seed_hash_hex": seed_hash.hex(),
                    "seed_key": seed_key,
                    "epochs": [],
                    "workers": {},
                    "hits": 0,
                    "source": source,
                },
            )

            hist["seed_hash_hex"] = seed_hash.hex()
            hist["seed_key"] = seed_key
            hist["hits"] = int(hist.get("hits", 0)) + 1
            hist["source"] = source

            epochs = hist.setdefault("epochs", [])
            if epoch not in epochs:
                epochs.append(epoch)
                if len(epochs) > 16:
                    del epochs[:-16]

            if worker_index is not None:
                workers = hist.setdefault("workers", {})
                workers[int(worker_index)] = {
                    "worker_index": int(worker_index),
                    "epoch": epoch,
                    "seed_key": seed_key,
                    "source": source,
                }

        seed_hist = self._seed_epoch_history.setdefault(
            seed_key,
            {
                "seed_key": seed_key,
                "seed_hash_hex": seed_hash.hex(),
                "first_epoch": epoch,
                "last_epoch": epoch,
                "hits": 0,
                "sources": {},
            },
        )
        seed_hist["last_epoch"] = epoch
        seed_hist["hits"] = int(seed_hist.get("hits", 0)) + 1
        seed_hist.setdefault("sources", {})[source] = int(
            seed_hist.setdefault("sources", {}).get(source, 0)
        ) + 1

        self._trim_history_locked()

    def _same_seed_ready_locked(
        self,
        *,
        seed_hash: bytes,
        generation: Optional[int] = None,
        worker_index: Optional[int] = None,
    ) -> Optional[int]:
        """
        Safe epoch batching fast path.

        Only returns an epoch when the ready seed exactly matches seed_hash.
        """
        if self._ready_seed != seed_hash or self._build_error is not None:
            return None

        epoch = int(self._ready_epoch)

        self._stats["same_seed_fast_path"] += 1

        if self._last_seed == seed_hash and self._last_epoch == epoch:
            self._same_seed_hits += 1
        else:
            self._last_seed = seed_hash
            self._last_epoch = epoch
            self._same_seed_hits = 1

        if self._same_seed_hits >= 3:
            self._stats["epoch_batch_hits"] += 1

            if self._same_seed_hits in (3, 8, 32, 128):
                self._evt_emit(
                    "epoch_batch",
                    details=(
                        f"seed={self._seed_key(seed_hash)} epoch={epoch} "
                        f"same_seed_hits={self._same_seed_hits}"
                    ),
                )

        self._note_epoch_history_locked(
            seed_hash=seed_hash,
            epoch=epoch,
            generation=generation,
            worker_index=worker_index,
            source="same_seed_batch",
        )

        return epoch

    def ensure_seed_ready_for_generation(
        self,
        seed_hash: bytes,
        *,
        generation: Optional[int] = None,
        worker_index: Optional[int] = None,
        job_age_ms: Optional[float] = None,
    ) -> int:
        """
        Generation-aware wrapper around ensure_seed_ready().

        The public ensure_seed_ready(seed_hash) behavior remains valid.
        This method adds metadata/history and safe same-seed batching.
        """
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        with self._cv:
            fast_epoch = self._same_seed_ready_locked(
                seed_hash=seed_hash,
                generation=generation,
                worker_index=worker_index,
            )
            if fast_epoch is not None:
                return int(fast_epoch)

        epoch = int(self.ensure_seed_ready(seed_hash))

        with self._cv:
            self._note_epoch_history_locked(
                seed_hash=seed_hash,
                epoch=epoch,
                generation=generation,
                worker_index=worker_index,
                source="ensure_generation",
            )

            if job_age_ms is not None:
                try:
                    if generation is not None and int(generation) in self.epoch_history:
                        self.epoch_history[int(generation)]["job_age_ms"] = float(job_age_ms)
                except Exception:
                    pass

        return epoch

    def warm_seed_hint(
        self,
        seed_hash: bytes,
        *,
        generation: Optional[int] = None,
        worker_index: Optional[int] = None,
    ) -> int:
        """
        Synchronously warm a real known seed hash.

        This does not guess the next RandomX seed. The caller must provide the
        actual seed_hash. Guessing generation + 1 is not safe.
        """
        self._stats["hint_warm_calls"] += 1

        epoch = int(
            self.ensure_seed_ready_for_generation(
                seed_hash,
                generation=generation,
                worker_index=worker_index,
            )
        )

        self._stats["hint_warm_success"] += 1

        self._evt_emit(
            "hint_warm",
            details=(
                f"seed={self._seed_key(bytes(seed_hash or b''))} "
                f"epoch={epoch} generation={generation} worker={worker_index}"
            ),
        )

        return epoch

    def ensure_seed_ready(self, seed_hash: bytes) -> int:
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        build_started_here = False
        seed_hex = seed_hash.hex()[:16]
        t0 = time.perf_counter()

        with self._cv:
            self._stats["build_requests"] += 1

            while True:
                fast_epoch = self._same_seed_ready_locked(seed_hash=seed_hash)
                if fast_epoch is not None:
                    return int(fast_epoch)

                if self._building_seed == seed_hash:
                    self._stats["build_waits"] += 1
                    self._evt_emit(
                        "build_wait",
                        details=f"seed={seed_hex} ready_epoch={self._ready_epoch}",
                    )
                    self._cv.wait()
                    continue

                if self._building_seed is None:
                    self._building_seed = seed_hash
                    self._build_error = None
                    self._stats["build_starts"] += 1
                    build_started_here = True
                    self._evt_emit(
                        "build_start",
                        details=f"seed={seed_hex} next_epoch={self._ready_epoch + 1}",
                    )
                    break

                self._stats["build_waits"] += 1
                self._evt_emit(
                    "build_wait",
                    details=f"seed={seed_hex} building_other_seed=1",
                )
                self._cv.wait()

        try:
            self.rx.ensure_seed(seed_hash)
        except BaseException as e:
            with self._cv:
                self._building_seed = None
                self._build_error = e
                self._stats["build_fail"] += 1
                self._cv.notify_all()

            if build_started_here:
                self._evt_emit(
                    "build_fail",
                    details=f"seed={seed_hex} error={type(e).__name__}: {e}",
                    force=True,
                )
            raise

        with self._cv:
            self._ready_seed = seed_hash
            self._ready_epoch += 1
            self._building_seed = None
            self._build_error = None
            self._stats["build_success"] += 1

            epoch = int(self._ready_epoch)
            self._last_seed = seed_hash
            self._last_epoch = epoch
            self._same_seed_hits = 1

            self._note_epoch_history_locked(
                seed_hash=seed_hash,
                epoch=epoch,
                source="build",
            )

            self._cv.notify_all()

        if build_started_here:
            elapsed = max(0.0, time.perf_counter() - t0)
            self._evt_emit(
                "build_done",
                details=f"seed={seed_hex} epoch={epoch} elapsed_sec={elapsed:.2f}",
                force=True,
            )

        return epoch

    def current_seed(self) -> bytes:
        with self._mu:
            return self._ready_seed

    def current_epoch(self) -> int:
        with self._mu:
            return int(self._ready_epoch)

    def snapshot(self) -> dict:
        with self._mu:
            return {
                "ready_seed_hex": self._ready_seed.hex() if self._ready_seed else "",
                "ready_epoch": int(self._ready_epoch),
                "building_seed_hex": self._building_seed.hex() if self._building_seed else "",
                "has_build_error": self._build_error is not None,
                "last_seed_hex": self._last_seed.hex() if self._last_seed else "",
                "last_epoch": int(self._last_epoch),
                "same_seed_hits": int(self._same_seed_hits),
                "stats": dict(self._stats),
                "epoch_history": {
                    int(k): {
                        **v,
                        "workers": {
                            int(wk): dict(wv)
                            for wk, wv in dict(v.get("workers", {})).items()
                        },
                    }
                    for k, v in self.epoch_history.items()
                },
                "seed_epoch_history": {
                    str(k): dict(v) for k, v in self._seed_epoch_history.items()
                },
            }


class RandomXVmPool(_ClassEventLogMixin):
    """
    Keeps one VM per worker and recreates it only when the RandomX dataset epoch
    changes.

    Patch behavior:
    - uses generation-aware dataset builder when available
    - tracks per-worker generation/epoch hints
    - supports synchronous warming of real next seed hints
    - avoids repeated ensure_seed_ready() during warm_workers()
    - tracks stale job age without unsafe early returns
    - never reuses a VM across a different dataset epoch
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

        # worker_index -> hint dict
        self._epoch_hints: dict[int, dict[str, Any]] = {}

        # Optional callable returning current job age in ms.
        self._job_age_provider: Optional[Callable[[], float]] = None

        self._stats = {
            "acquire_calls": 0,
            "vm_creates": 0,
            "vm_reuses": 0,
            "vm_rebuilds": 0,
            "vm_destroy": 0,
            "warm_calls": 0,
            "warm_vm_reuses": 0,
            "hint_notes": 0,
            "hint_warm_calls": 0,
            "hint_warm_success": 0,
            "stale_observed": 0,
            "generation_hint_hits": 0,
        }

        self._evt_init(
            class_prefix="RandomXVmPool",
            logger=logger,
            cooldowns={
                "vm_create": 60.0,
                "vm_rebuild": 60.0,
                "warm": 90.0,
                "hint": 90.0,
                "stale": 90.0,
                "close": 120.0,
            },
            phrases={
                "vm_create": [
                    "a worker VM came online",
                    "the pool opened a fresh VM lane",
                    "a new RandomX VM stepped into place",
                    "the pool spun up a worker VM",
                ],
                "vm_rebuild": [
                    "a worker VM rolled onto a new epoch",
                    "the pool rebuilt a VM for fresh seed state",
                    "one VM shed its old epoch and came back fresh",
                    "the VM lane was rebuilt for current work",
                ],
                "warm": [
                    "the VM pool stretched before live work",
                    "worker VMs were warmed onto the current seed",
                    "the pool prepped its active lanes",
                    "seed warmth spread across the worker VMs",
                ],
                "hint": [
                    "an epoch hint was recorded for a worker",
                    "the pool cached a worker generation hint",
                    "a VM lane received a next-seed hint",
                    "worker epoch metadata was refreshed",
                ],
                "stale": [
                    "the VM pool noticed stale-age pressure",
                    "a worker acquire arrived on an old job",
                    "stale job age was recorded before VM acquire",
                    "old work was observed during VM preparation",
                ],
                "close": [
                    "the VM pool cooled off",
                    "worker VMs were wound down",
                    "the pool settled back to idle",
                    "the VM lanes stood down cleanly",
                ],
            },
        )

    def _log(self, msg: str) -> None:
        try:
            self.logger(msg)
        except Exception:
            pass

    def set_job_age_provider(self, provider: Optional[Callable[[], float]]) -> None:
        """
        Optional hook from JITWorker:

            self._vm_pool.set_job_age_provider(self._dispatch.current_job_age_ms)

        Existing code does not need to call this.
        """
        with self._mu:
            self._job_age_provider = provider

    def _current_job_age_ms(self) -> float:
        provider = None
        with self._mu:
            provider = self._job_age_provider

        if provider is None:
            return 0.0

        try:
            return max(0.0, float(provider() or 0.0))
        except Exception:
            return 0.0

    def note_worker_generation(
        self,
        worker_index: int,
        generation: int,
        *,
        seed_hash: Optional[bytes] = None,
        next_seed_hash: Optional[bytes] = None,
    ) -> None:
        """
        Optional hint hook from JITWorker.

        Safe usage:
            self._vm_pool.note_worker_generation(
                st.worker_index,
                st.assigned_generation,
                seed_hash=bytes(job.seed_hash or b""),
            )

        next_seed_hash must be a real known seed hash, not generation + 1.
        """
        idx = int(worker_index)
        gen = int(generation)

        with self._mu:
            hint = self._epoch_hints.setdefault(
                idx,
                {
                    "worker_index": idx,
                    "generation": 0,
                    "last_generation": 0,
                    "stable_count": 0,
                    "seed_hash": b"",
                    "next_seed_hash": b"",
                    "hint_epoch": 0,
                    "last_epoch": 0,
                    "last_job_age_ms": 0.0,
                },
            )

            last_gen = int(hint.get("generation", 0))
            if gen == last_gen:
                hint["stable_count"] = int(hint.get("stable_count", 0)) + 1
            else:
                hint["last_generation"] = last_gen
                hint["generation"] = gen
                hint["stable_count"] = 1

            if seed_hash is not None:
                hint["seed_hash"] = bytes(seed_hash or b"")

            if next_seed_hash is not None:
                hint["next_seed_hash"] = bytes(next_seed_hash or b"")

            self._stats["hint_notes"] += 1

        if self._stats["hint_notes"] in (1, 8, 32, 128):
            self._evt_emit(
                "hint",
                details=f"worker={idx} generation={gen}",
            )

    def _destroy_entry_vm_locked(self, entry: dict[str, Any]) -> None:
        vm = entry.get("vm")
        if vm is not None:
            try:
                self.rx.destroy_vm(vm)
            except Exception:
                pass
            entry["vm"] = None
            self._stats["vm_destroy"] += 1

    def _ensure_epoch_for_worker(self, worker_index: int, seed_hash: bytes) -> int:
        idx = int(worker_index)
        seed_hash = bytes(seed_hash or b"")

        with self._mu:
            hint = dict(self._epoch_hints.get(idx, {}))

        generation = hint.get("generation", None)
        job_age_ms = self._current_job_age_ms()

        if job_age_ms >= 2000.0:
            with self._mu:
                self._stats["stale_observed"] += 1
                if idx in self._epoch_hints:
                    self._epoch_hints[idx]["last_job_age_ms"] = float(job_age_ms)

            self._evt_emit(
                "stale",
                details=f"worker={idx} job_age_ms={job_age_ms:.1f}",
            )

        ensure_for_gen = getattr(self.dataset_builder, "ensure_seed_ready_for_generation", None)
        if callable(ensure_for_gen):
            epoch = int(
                ensure_for_gen(
                    seed_hash,
                    generation=None if generation is None else int(generation),
                    worker_index=idx,
                    job_age_ms=job_age_ms,
                )
            )
        else:
            epoch = int(self.dataset_builder.ensure_seed_ready(seed_hash))

        with self._mu:
            hint_ref = self._epoch_hints.setdefault(
                idx,
                {
                    "worker_index": idx,
                    "generation": 0,
                    "last_generation": 0,
                    "stable_count": 0,
                    "seed_hash": b"",
                    "next_seed_hash": b"",
                    "hint_epoch": 0,
                    "last_epoch": 0,
                    "last_job_age_ms": 0.0,
                },
            )
            hint_ref["last_epoch"] = epoch
            hint_ref["seed_hash"] = seed_hash
            hint_ref["last_job_age_ms"] = float(job_age_ms)

            if generation is not None:
                self._stats["generation_hint_hits"] += 1

        return epoch

    def _get_or_create_vm_locked(
        self,
        *,
        worker_index: int,
        seed_hash: bytes,
        epoch: int,
    ) -> tuple[Any, int, str]:
        idx = int(worker_index)
        epoch = int(epoch)

        entry = self._entries.get(idx)
        if entry is None:
            vm = self.rx.create_vm()
            self._entries[idx] = {
                "vm": vm,
                "epoch": epoch,
                "seed_hash": seed_hash,
            }
            self._stats["vm_creates"] += 1
            return vm, epoch, "create"

        if entry.get("vm") is not None and int(entry.get("epoch", 0)) == epoch:
            self._stats["vm_reuses"] += 1
            return entry["vm"], epoch, "reuse"

        self._destroy_entry_vm_locked(entry)

        vm = self.rx.create_vm()
        entry["vm"] = vm
        entry["epoch"] = epoch
        entry["seed_hash"] = seed_hash
        self._stats["vm_rebuilds"] += 1

        return vm, epoch, "rebuild"

    def acquire_for_worker(self, worker_index: int, seed_hash: bytes) -> tuple[Any, int]:
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        idx = int(worker_index)
        epoch = self._ensure_epoch_for_worker(idx, seed_hash)

        with self._mu:
            self._stats["acquire_calls"] += 1

            vm, epoch, action = self._get_or_create_vm_locked(
                worker_index=idx,
                seed_hash=seed_hash,
                epoch=epoch,
            )

        if action == "create":
            self._evt_emit(
                "vm_create",
                details=f"worker={idx} epoch={epoch} seed={seed_hash.hex()[:16]}",
            )
        elif action == "rebuild":
            self._evt_emit(
                "vm_rebuild",
                details=f"worker={idx} epoch={epoch} seed={seed_hash.hex()[:16]}",
            )

        return vm, int(epoch)

    def warm_next_epoch_hint(
        self,
        worker_index: int,
        seed_hash: bytes,
        *,
        generation: Optional[int] = None,
    ) -> int:
        """
        Synchronously warm a real known next seed hash.

        This does not guess next epoch from generation + 1. RandomX needs an
        actual seed_hash.
        """
        idx = int(worker_index)
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        self._stats["hint_warm_calls"] += 1

        with self._mu:
            self._epoch_hints.setdefault(
                idx,
                {
                    "worker_index": idx,
                    "generation": int(generation or 0),
                    "last_generation": 0,
                    "stable_count": 0,
                    "seed_hash": b"",
                    "next_seed_hash": seed_hash,
                    "hint_epoch": 0,
                    "last_epoch": 0,
                    "last_job_age_ms": 0.0,
                },
            )["next_seed_hash"] = seed_hash

        warm_hint = getattr(self.dataset_builder, "warm_seed_hint", None)
        if callable(warm_hint):
            epoch = int(
                warm_hint(
                    seed_hash,
                    generation=generation,
                    worker_index=idx,
                )
            )
        else:
            epoch = int(self.dataset_builder.ensure_seed_ready(seed_hash))

        with self._mu:
            hint = self._epoch_hints.setdefault(idx, {"worker_index": idx})
            hint["hint_epoch"] = epoch
            hint["next_seed_hash"] = seed_hash
            self._stats["hint_warm_success"] += 1

        self._evt_emit(
            "hint",
            details=(
                f"worker={idx} warmed_hint_epoch={epoch} "
                f"generation={generation} seed={seed_hash.hex()[:16]}"
            ),
        )

        return epoch

    def warm_workers(self, worker_indices: list[int], seed_hash: bytes) -> int:
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        indices = [int(i) for i in (worker_indices or [])]
        self._stats["warm_calls"] += 1

        # Ensure once, then create/reuse VMs under pool lock without repeating
        # dataset ensure for every worker.
        ensure_for_gen = getattr(self.dataset_builder, "ensure_seed_ready_for_generation", None)

        if callable(ensure_for_gen):
            epoch = int(
                ensure_for_gen(
                    seed_hash,
                    generation=None,
                    worker_index=None,
                    job_age_ms=self._current_job_age_ms(),
                )
            )
        else:
            epoch = int(self.dataset_builder.ensure_seed_ready(seed_hash))

        created = 0
        reused = 0
        rebuilt = 0

        with self._mu:
            for idx in indices:
                vm, _epoch, action = self._get_or_create_vm_locked(
                    worker_index=idx,
                    seed_hash=seed_hash,
                    epoch=epoch,
                )

                if action == "create":
                    created += 1
                elif action == "reuse":
                    reused += 1
                    self._stats["warm_vm_reuses"] += 1
                elif action == "rebuild":
                    rebuilt += 1

                hint = self._epoch_hints.setdefault(
                    idx,
                    {
                        "worker_index": idx,
                        "generation": 0,
                        "last_generation": 0,
                        "stable_count": 0,
                        "seed_hash": b"",
                        "next_seed_hash": b"",
                        "hint_epoch": 0,
                        "last_epoch": 0,
                        "last_job_age_ms": 0.0,
                    },
                )
                hint["seed_hash"] = seed_hash
                hint["last_epoch"] = int(epoch)

        if indices:
            self._evt_emit(
                "warm",
                details=(
                    f"workers={len(indices)} epoch={epoch} seed={seed_hash.hex()[:16]} "
                    f"created={created} reused={reused} rebuilt={rebuilt}"
                ),
            )

        return int(epoch)

    def close(self) -> None:
        with self._mu:
            count = 0
            for entry in self._entries.values():
                if entry.get("vm") is not None:
                    count += 1
                self._destroy_entry_vm_locked(entry)

            self._entries.clear()
            self._epoch_hints.clear()

        self._evt_emit("close", details=f"destroyed_vms={count}", force=True)

    def snapshot(self) -> dict:
        with self._mu:
            return {
                "pool_size": len(self._entries),
                "stats": dict(self._stats),
                "epoch_hints": {
                    int(idx): {
                        "worker_index": int(hint.get("worker_index", idx)),
                        "generation": int(hint.get("generation", 0)),
                        "last_generation": int(hint.get("last_generation", 0)),
                        "stable_count": int(hint.get("stable_count", 0)),
                        "seed_hash_hex": bytes(hint.get("seed_hash", b"")).hex(),
                        "next_seed_hash_hex": bytes(hint.get("next_seed_hash", b"")).hex(),
                        "hint_epoch": int(hint.get("hint_epoch", 0)),
                        "last_epoch": int(hint.get("last_epoch", 0)),
                        "last_job_age_ms": float(hint.get("last_job_age_ms", 0.0)),
                    }
                    for idx, hint in self._epoch_hints.items()
                },
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
    assigned_stride: int = 1

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

    candidate_batch: Optional["_CandidateBatch"] = None
    nonce_writer: Optional["_NonceStrideWriter"] = None
    tail64_probe: Optional["_Tail64Probe"] = None

class JITWorker:
    """
    Safe JITWorker using MoneroHashLoop.dll.

    Important:
        Do NOT XOR arbitrary blob/seed bytes to create thread-specific VM states.

        For Monero/P2Pool, the share verifier expects the hash of the exact job
        blob with a valid nonce. Mutating seed bytes or non-nonce blob bytes
        creates a different proof and will be rejected.

    This version:
        - keeps exact constructor/hash_job/stop signatures
        - keeps native MoneroHashLoop.dll hot loop
        - keeps RandomX VM pool reuse
        - keeps candidate ranking/diversity
        - keeps deterministic per-generation lane permutation
        - guarantees each worker receives a unique nonce residue lane
        - synchronizes native current_generation before workers start hashing
        - tracks best share per worker/generation
        - round-robin balances candidates across worker lanes
        - validates duplicate candidates in logs/snapshots
        - scales native candidate buffer for high-volatility jobs
        - avoids duplicate nonce work without corrupting blob/seed
        - keeps final dedupe as protection against native/result bugs

    Optional environment settings:
        MONERO_LANE_VARIANT=A|B|C
        JITWORKER_LANE_VARIANT=A|B|C

        MONERO_NATIVE_MAX_CANDIDATES=256
        JITWORKER_NATIVE_MAX_CANDIDATES=256

        MONERO_DEBUG_NONCES=1
        JITWORKER_DEBUG_NONCES=1
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

        self._native_stop_flag = ctypes.c_int(0)

        # Native stale detection reads this pointer.
        #
        # hash_job() updates this BEFORE workers start hashing.
        # Worker callbacks must NOT overwrite it with their own generation.
        self._native_generation = ctypes.c_uint64(0)

        self._hot_hash = None
        self._hot_hash_error = ""
        self._hot_hash_hash_fn_ptr = 0

        self._unsafe_blob_xor_enabled = False

        self._lane_permutation_variant = self._resolve_lane_permutation_variant()
        self._native_max_candidates_cap = self._read_int_config(
            names=(
                "MONERO_NATIVE_MAX_CANDIDATES",
                "JITWORKER_NATIVE_MAX_CANDIDATES",
            ),
            default=256,
            minimum=8,
            maximum=4096,
        )
        self._debug_unique_nonces = self._read_bool_config(
            names=(
                "MONERO_DEBUG_NONCES",
                "JITWORKER_DEBUG_NONCES",
            ),
            default=True,
        )

        self._last_lane_ids: list[int] = []
        self._last_generation = 0
        self._last_threads_used = 0

        self._last_shares_found_this_round = 0
        self._last_duplicate_candidate_count = 0
        self._last_duplicate_tail64_count = 0
        self._last_round_worker_share_counts: dict[int, int] = {}
        self._last_unique_share_snapshot: dict = {
            "mode": "best_share_per_worker_generation",
            "threads_active": 0,
            "shares_found_this_round": 0,
            "duplicate_candidate_count": 0,
            "duplicate_tail64_count": 0,
            "worker_share_counts": {},
        }

        try:
            self._hot_hash = MoneroHashLoopDLL.load_same_dir()
            self._hot_hash_hash_fn_ptr = self._resolve_native_hash_fn_ptr()
            self.logger(
                f"[JITWorker] MoneroHashLoop.dll loaded: "
                f"path={self._hot_hash.dll_path} "
                f"prefix={self._hot_hash.prefix} "
                f"version={self._hot_hash.version()} "
                f"hash_fn_ptr=0x{self._hot_hash_hash_fn_ptr:x}"
            )
        except Exception as e:
            self._hot_hash = None
            self._hot_hash_hash_fn_ptr = 0
            self._hot_hash_error = f"{type(e).__name__}: {e}"
            self.logger(
                f"[JITWorker] MoneroHashLoop.dll unavailable, worker will report native errors: "
                f"{self._hot_hash_error}"
            )

        self._dispatch = _JobDispatchCoordinator(
            hashed_job_start=True,
            logger=self.logger,
        )

        self._selector = _CandidateSelector(
            max_keep_default=16,
            logger=self.logger,
        )

        self._share_diversity = _ShareDiversityCoordinator(
            logger=self.logger,
            ttl_ms=18000.0,
            max_recent=8192,
            stripe_shift=12,
        )

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

        self._round_candidate_batch = _CandidateBatch(
            owner_key="round-batch",
            max_keep_default=32,
            logger=self.logger,
        )

        self._bootstrap_workers()

    @staticmethod
    def _read_int_config(
        *,
        names: tuple[str, ...],
        default: int,
        minimum: int,
        maximum: int,
    ) -> int:
        try:
            import os

            for name in names:
                raw = os.getenv(name)
                if raw is None:
                    continue

                try:
                    value = int(str(raw).strip())
                    return max(int(minimum), min(int(maximum), value))
                except Exception:
                    continue
        except Exception:
            pass

        return max(int(minimum), min(int(maximum), int(default)))

    @staticmethod
    def _read_bool_config(
        *,
        names: tuple[str, ...],
        default: bool,
    ) -> bool:
        try:
            import os

            for name in names:
                raw = os.getenv(name)
                if raw is None:
                    continue

                text = str(raw).strip().lower()
                if text in {"1", "true", "yes", "y", "on", "enable", "enabled"}:
                    return True
                if text in {"0", "false", "no", "n", "off", "disable", "disabled"}:
                    return False
        except Exception:
            pass

        return bool(default)

    def _resolve_lane_permutation_variant(self) -> str:
        values = []

        for obj in (
            self.python_usage,
            self.jit,
            self.rx,
            getattr(self.jit, "config", None),
            getattr(self.rx, "config", None),
        ):
            if obj is None:
                continue

            for attr in (
                "lane_permutation_variant",
                "monero_lane_variant",
                "jitworker_lane_variant",
                "nonce_lane_variant",
            ):
                try:
                    value = getattr(obj, attr, None)
                    if value is not None:
                        values.append(value)
                except Exception:
                    pass

        try:
            import os

            values.append(os.getenv("MONERO_LANE_VARIANT"))
            values.append(os.getenv("JITWORKER_LANE_VARIANT"))
        except Exception:
            pass

        for value in values:
            variant = self._normalize_lane_variant(value)
            if variant:
                return variant

        return "A"

    @staticmethod
    def _normalize_lane_variant(value) -> str:
        if value is None:
            return ""

        text = str(value).strip().lower()
        text = text.replace("-", "_").replace(" ", "_")

        if text in {
            "a",
            "variant_a",
            "aggressive",
            "aggressive_residue_rotation",
            "residue_rotation",
            "golden",
            "golden_ratio",
        }:
            return "A"

        if text in {
            "b",
            "variant_b",
            "fixed",
            "fixed_step",
            "rotated_start",
        }:
            return "B"

        if text in {
            "c",
            "variant_c",
            "dual",
            "dual_magic",
            "dual_magic_rotation",
        }:
            return "C"

        return ""

    def _resolve_native_hash_fn_ptr(self) -> int:
        """
        Resolve native randomx_calculate_hash address from the RandomX wrapper.

        This does not create or own RandomX.
        It only gets the function pointer for MoneroHashLoop.dll.
        """
        if self._hot_hash is None:
            return 0

        try:
            ptr = int(self._hot_hash.randomx_hash_function_address(self.rx))
            if ptr:
                return ptr
        except Exception:
            pass

        candidates = [
            self.rx,
            getattr(self.rx, "lib", None),
            getattr(self.rx, "_lib", None),
            getattr(self.rx, "dll", None),
            getattr(self.rx, "_dll", None),
            getattr(self.rx, "randomx_dll", None),
        ]

        for obj in candidates:
            if obj is None:
                continue

            fn = getattr(obj, "randomx_calculate_hash", None)
            if fn is None:
                continue

            try:
                ptr = int(MoneroHashLoopDLL.address_of_function(fn))
                if ptr:
                    return ptr
            except Exception:
                continue

        raise RuntimeError(
            "Could not resolve native randomx_calculate_hash pointer from RandomX wrapper"
        )

    def _resolve_native_vm_ptr(self, vm) -> int:
        """
        Resolve randomx_vm* address from a VM object returned by RandomXVmPool.
        """
        if self._hot_hash is None:
            return 0

        try:
            ptr = int(self._hot_hash.randomx_vm_address(vm))
            if ptr:
                return ptr
        except Exception:
            pass

        if vm is None:
            return 0

        if isinstance(vm, int):
            return int(vm)

        if isinstance(vm, ctypes.c_void_p):
            return int(vm.value or 0)

        try:
            return int(ctypes.cast(vm, ctypes.c_void_p).value or 0)
        except Exception:
            return 0

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
        """
        Lower mask on older jobs.

        Native meaning:
            mask=63 checks generation every 64 hashes.
            mask=31 checks every 32 hashes.
            mask=15 checks every 16 hashes.
            mask=7 checks every 8 hashes.
        """
        age_ms = self._dispatch.current_job_age_ms()

        if age_ms < 150.0:
            return 63
        if age_ms < 400.0:
            return 31
        if age_ms < 900.0:
            return 15

        return 7

    @staticmethod
    def _gcd(a: int, b: int) -> int:
        a = abs(int(a))
        b = abs(int(b))

        while b:
            a, b = b, a % b

        return a

    def _make_coprime_step(self, n: int, step: int) -> int:
        n = max(1, int(n))
        if n <= 1:
            return 1

        step = int(step) % n
        if step <= 0:
            step = 1

        guard = 0
        while self._gcd(step, n) != 1:
            step = (step + 1) % n
            if step <= 0:
                step = 1

            guard += 1
            if guard > n + 4:
                return 1

        return int(step)

    def _build_lane_sequence(self, n: int, start: int, step: int) -> list[int]:
        n = max(1, int(n))
        if n == 1:
            return [0]

        step = self._make_coprime_step(n, step)
        start = int(start) % n

        lanes: list[int] = []
        seen: set[int] = set()

        x = start
        for _ in range(n):
            lane = int(x % n)

            if lane not in seen:
                lanes.append(lane)
                seen.add(lane)

            x += step

        if len(lanes) != n:
            lanes = list(range(n))

        return lanes

    def _lane_permutation_variant_a(self, n: int, generation: int) -> list[int]:
        n = max(1, int(n))
        if n == 1:
            return [0]

        gen = int(generation) & 0xFFFFFFFFFFFFFFFF

        magic1 = 0x9E3779B97F4A7C15
        magic2 = 0xD1B54A32D192ED03
        magic_start = 0xA0761D6478BD642F

        step = int((gen * magic1 + magic2) % n)
        start = int((gen ^ (gen >> 17) ^ magic_start) % n)

        return self._build_lane_sequence(n, start, step)

    def _lane_permutation_variant_b(self, n: int, generation: int) -> list[int]:
        n = max(1, int(n))
        if n == 1:
            return [0]

        gen = int(generation) & 0xFFFFFFFFFFFFFFFF

        fixed_step = 3
        magic_start = 0xA0761D6478BD642F

        step = self._make_coprime_step(n, fixed_step)
        start = int((gen ^ (gen >> 17) ^ magic_start) % n)

        return self._build_lane_sequence(n, start, step)

    def _lane_permutation_variant_c(self, n: int, generation: int) -> list[int]:
        n = max(1, int(n))
        if n == 1:
            return [0]

        gen = int(generation) & 0xFFFFFFFFFFFFFFFF

        magic3 = 0x5DEECE66D97F4A7C15
        magic4 = 0xB2B54A32D192ED03

        step = int((gen * magic3 + magic4) % n)
        start = int((gen ^ (gen >> 25)) % n)

        return self._build_lane_sequence(n, start, step)

    def _lane_permutation(self, n: int, generation: int) -> list[int]:
        """
        Build a unique lane assignment for this generation.

        Every lane appears exactly once:
            worker i hashes start + lane[i], then + n, + 2n, ...

        This gives diversity without overlapping nonce work and without changing
        the RandomX seed/blob.
        """
        n = max(1, int(n))
        if n == 1:
            return [0]

        variant = self._lane_permutation_variant

        try:
            if variant == "B":
                lanes = self._lane_permutation_variant_b(n, generation)
            elif variant == "C":
                lanes = self._lane_permutation_variant_c(n, generation)
            else:
                lanes = self._lane_permutation_variant_a(n, generation)
        except Exception as e:
            self.logger(
                f"[JITWorker] lane permutation failed variant={variant}: "
                f"{type(e).__name__}: {e}; falling back to range lanes"
            )
            lanes = list(range(n))

        if len(lanes) != n or len(set(lanes)) != n:
            self.logger(
                f"[JITWorker] invalid lane permutation variant={variant} "
                f"n={n} generation={generation}; falling back to range lanes"
            )
            lanes = list(range(n))

        return lanes

    @staticmethod
    def _candidate_identity(item: dict) -> tuple:
        nonce = int(item.get("nonce_u32", 0)) & 0xFFFFFFFF
        hash_hex = str(item.get("hash_hex", ""))

        return nonce, hash_hex

    @staticmethod
    def _candidate_tail64(item: dict) -> int:
        return int(item.get("tail64", item.get("_tail64", 0))) & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def _candidate_nonce(item: dict) -> int:
        return int(item.get("nonce_u32", item.get("_nonce", 0))) & 0xFFFFFFFF

    def _dedupe_candidates(self, candidates: list[dict]) -> list[dict]:
        out: list[dict] = []
        seen: set[tuple] = set()

        for item in candidates or []:
            try:
                key = self._candidate_identity(item)
            except Exception:
                continue

            if key in seen:
                continue

            seen.add(key)
            out.append(item)

        return out

    def _strip_candidate_debug_fields(self, candidates: list[dict]) -> list[dict]:
        out: list[dict] = []

        for c in candidates or []:
            try:
                out.append({k: v for k, v in dict(c).items() if not str(k).startswith("_")})
            except Exception:
                continue

        return out

    def _bootstrap_workers(self) -> None:
        jit_version = "unavailable"

        try:
            jit_version = str(self.jit.version())
        except Exception:
            pass

        hot_hash_status = "unavailable"

        if self._hot_hash is not None and self._hot_hash_hash_fn_ptr:
            hot_hash_status = (
                f"loaded prefix={self._hot_hash.prefix} "
                f"version={self._hot_hash.version()} "
                f"hash_fn_ptr=0x{self._hot_hash_hash_fn_ptr:x}"
            )
        elif self._hot_hash_error:
            hot_hash_status = self._hot_hash_error

        for i in range(self.threads):
            st = _ThreadState(
                worker_index=i,
                out_buf=(c_ubyte * 32)(),
                found=[],
                start_event=threading.Event(),
                done_event=threading.Event(),
                stop_event=self._stop,
                candidate_batch=_CandidateBatch(
                    owner_key=f"worker-batch-{i}",
                    max_keep_default=max(8, self.batch_size // 64),
                    logger=self.logger,
                ),
            )

            st.callback = self._make_callback(st)
            st.thunk = None
            st.exec_mode = self._exec.bind_worker(st)

            st.assigned_lane_id = 0
            st.assigned_stride = 1
            st.assigned_generation = 0
            st.assigned_start_nonce = 0
            st.assigned_count = 0
            st.assigned_max_results = 0
            st.assigned_job = None

            # Unique nonce debugging.
            try:
                st.unique_nonce_tracker = threading.local()
            except Exception:
                st.unique_nonce_tracker = None

            # Unique share tracking.
            st.best_share_per_generation = {}
            st.best_share_lock = threading.RLock()

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
            f"monero_hash_loop={hot_hash_status} "
            f"lane_variant={self._lane_permutation_variant} "
            f"native_max_candidates_cap={self._native_max_candidates_cap} "
            f"debug_unique_nonces={self._debug_unique_nonces} "
            f"unsafe_blob_xor={self._unsafe_blob_xor_enabled} "
            f"(native hot loop + vm pool + unique nonce lanes + unique share tracking)"
        )

    def _max_candidates_for_job(self, job: "MoneroJob", keep_best: int) -> int:
        keep_best = max(1, int(keep_best))
        cap = max(8, int(self._native_max_candidates_cap))

        pool_type = ""
        try:
            pool_type = str(getattr(job, "pool_type", "") or "").strip().lower()
        except Exception:
            pool_type = ""

        volatility = ""
        try:
            volatility = str(getattr(job, "volatility", "") or "").strip().lower()
        except Exception:
            volatility = ""

        high_volatility = False

        if pool_type in {
            "high_volatility",
            "volatile",
            "young",
            "new",
            "fast_jobs",
            "fast",
        }:
            high_volatility = True

        if volatility in {
            "high",
            "high_volatility",
            "volatile",
            "fast",
        }:
            high_volatility = True

        for attr in (
            "high_volatility",
            "volatile_pool",
            "pool_volatile",
            "is_volatile",
        ):
            try:
                if bool(getattr(job, attr, False)):
                    high_volatility = True
                    break
            except Exception:
                pass

        multiplier = 8 if high_volatility else 4
        return max(8, min(cap, keep_best * multiplier))

    def _debug_track_unique_nonces(self, st: _ThreadState) -> None:
        if not self._debug_unique_nonces:
            return

        try:
            tracker = getattr(st, "unique_nonce_tracker", None)
            if tracker is None:
                return

            generation = int(getattr(st, "assigned_generation", 0) or 0)

            if getattr(tracker, "generation", None) != generation:
                tracker.generation = generation
                tracker.nonce_seen = set()
                tracker.logged_count = 0

            nonce_seen = getattr(tracker, "nonce_seen", None)
            if nonce_seen is None:
                nonce_seen = set()
                tracker.nonce_seen = nonce_seen

            logged_count = int(getattr(tracker, "logged_count", 0) or 0)

            for c in st.found or []:
                try:
                    n = int(c.get("nonce_u32", 0)) & 0xFFFFFFFF
                except Exception:
                    continue

                if n in nonce_seen:
                    self.logger(
                        f"[JITWorker-{st.worker_index}] duplicate_candidate_nonce "
                        f"generation={generation} nonce={n} "
                        f"lane={getattr(st, 'assigned_lane_id', 0)} "
                        f"start_nonce={int(getattr(st, 'assigned_start_nonce', 0)) & 0xFFFFFFFF} "
                        f"stride={int(getattr(st, 'assigned_stride', 1))}"
                    )
                    continue

                nonce_seen.add(n)

                if logged_count < 8:
                    tail64 = self._candidate_tail64(c)

                    self.logger(
                        f"[JITWorker-{st.worker_index}] "
                        f"unique_nonce={n} "
                        f"tail64=0x{tail64:016X} "
                        f"generation={generation} "
                        f"lane={getattr(st, 'assigned_lane_id', 0)} "
                        f"start_nonce={int(getattr(st, 'assigned_start_nonce', 0)) & 0xFFFFFFFF} "
                        f"stride={int(getattr(st, 'assigned_stride', 1))}"
                    )
                    logged_count += 1
                    tracker.logged_count = logged_count

            if len(nonce_seen) > 65536:
                tracker.nonce_seen = set(list(nonce_seen)[-8192:])

        except Exception:
            pass

    def _track_best_share_per_generation(self, st: _ThreadState) -> None:
        """
        Track the best candidate/share per worker/generation.

        Lower tail64 is better.

        Stored shape:
            st.best_share_per_generation[generation] = {
                "candidate": candidate copy,
                "tail64": int,
                "nonce": int,
                "lane_id": int,
                "worker_index": int,
            }
        """
        try:
            if not st.found:
                return

            gen = int(getattr(st, "assigned_generation", 0) or 0)
            if gen <= 0:
                return

            best_map = getattr(st, "best_share_per_generation", None)
            if best_map is None:
                best_map = {}
                st.best_share_per_generation = best_map

            lock = getattr(st, "best_share_lock", None)

            def _update() -> None:
                for c in st.found or []:
                    try:
                        candidate = dict(c)
                        tail64 = self._candidate_tail64(candidate)
                        nonce = self._candidate_nonce(candidate)
                    except Exception:
                        continue

                    current = best_map.get(gen)

                    replace = False
                    if current is None:
                        replace = True
                    else:
                        old_tail = int(current.get("tail64", 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
                        old_nonce = int(current.get("nonce", 0xFFFFFFFF)) & 0xFFFFFFFF

                        if tail64 < old_tail:
                            replace = True
                        elif tail64 == old_tail and nonce < old_nonce:
                            replace = True

                    if replace:
                        best_map[gen] = {
                            "candidate": candidate.copy(),
                            "tail64": tail64,
                            "nonce": nonce,
                            "lane_id": int(getattr(st, "assigned_lane_id", 0)),
                            "worker_index": int(getattr(st, "worker_index", -1)),
                        }

                # Bound memory to recent generations.
                if len(best_map) > 128:
                    keep_keys = sorted(best_map.keys())[-64:]
                    keep = {k: best_map[k] for k in keep_keys if k in best_map}
                    best_map.clear()
                    best_map.update(keep)

            if lock is not None:
                with lock:
                    _update()
            else:
                _update()

        except Exception:
            pass

    def _collect_annotated_worker_candidates(
        self,
        active_states: list["_ThreadState"],
        generation: int,
    ) -> list[dict]:
        """
        Collect candidates from every worker and preserve worker/lane metadata.

        Candidate identity remains nonce+hash_hex.
        Duplicate tail64 is logged separately because equal tail64 does not
        necessarily mean equal share, but it is useful for debugging.
        """
        annotated: list[dict] = []
        seen_identities: set[tuple] = set()
        seen_tail64_by_generation: set[tuple[int, int]] = set()

        duplicate_candidate_count = 0
        duplicate_tail64_count = 0
        worker_counts: dict[int, int] = {}

        for st in active_states:
            worker_index = int(getattr(st, "worker_index", -1))
            lane_id = int(getattr(st, "assigned_lane_id", 0))
            gen = int(getattr(st, "assigned_generation", generation) or generation)

            for c in st.found or []:
                try:
                    cc = dict(c)
                    identity = self._candidate_identity(cc)
                    tail64 = self._candidate_tail64(cc)
                    nonce = self._candidate_nonce(cc)
                except Exception:
                    continue

                if identity in seen_identities:
                    duplicate_candidate_count += 1
                    continue

                seen_identities.add(identity)

                tail_key = (gen, tail64)
                if tail_key in seen_tail64_by_generation:
                    duplicate_tail64_count += 1
                else:
                    seen_tail64_by_generation.add(tail_key)

                cc["_found_by_thread"] = worker_index
                cc["_generation"] = gen
                cc["_lane_id"] = lane_id
                cc["_tail64"] = tail64
                cc["_nonce"] = nonce

                annotated.append(cc)
                worker_counts[worker_index] = worker_counts.get(worker_index, 0) + 1

        self._last_duplicate_candidate_count = int(duplicate_candidate_count)
        self._last_duplicate_tail64_count = int(duplicate_tail64_count)
        self._last_round_worker_share_counts = dict(worker_counts)

        if duplicate_candidate_count:
            self.logger(
                f"[JITWorker] duplicate candidate identities detected: "
                f"generation={generation} count={duplicate_candidate_count}"
            )

        if duplicate_tail64_count:
            self.logger(
                f"[JITWorker] duplicate tail64 values detected: "
                f"generation={generation} count={duplicate_tail64_count}"
            )

        return annotated

    def _round_robin_annotated_candidates(
        self,
        annotated: list[dict],
        limit: int,
    ) -> list[dict]:
        """
        Balance candidate ordering across workers.

        Lower tail64 is better.

        The output keeps debug fields. Strip debug fields only at final export.
        """
        limit = max(1, int(limit))
        if not annotated:
            return []

        queues: dict[int, list[dict]] = {}

        for c in annotated:
            try:
                worker_id = int(c.get("_found_by_thread", -1))
            except Exception:
                worker_id = -1

            queues.setdefault(worker_id, []).append(c)

        for worker_id, q in queues.items():
            q.sort(
                key=lambda x: (
                    self._candidate_tail64(x),
                    self._candidate_nonce(x),
                    int(x.get("_lane_id", 0)),
                )
            )

        worker_order = sorted(
            queues.keys(),
            key=lambda wid: (
                self._candidate_tail64(queues[wid][0]) if queues.get(wid) else 0xFFFFFFFFFFFFFFFF,
                wid,
            ),
        )

        out: list[dict] = []
        made_progress = True

        while made_progress and len(out) < limit:
            made_progress = False

            for worker_id in worker_order:
                q = queues.get(worker_id) or []
                if not q:
                    continue

                out.append(q.pop(0))
                made_progress = True

                if len(out) >= limit:
                    break

        return out

    def _reapply_worker_metadata(
        self,
        ranked_pool: list[dict],
        annotated_source: list[dict],
    ) -> list[dict]:
        """
        Reattach worker/lane metadata after _selector.rank(), if rank preserved
        candidate identity but stripped/rewrapped dicts.
        """
        meta_by_identity: dict[tuple, dict] = {}

        for c in annotated_source or []:
            try:
                identity = self._candidate_identity(c)
            except Exception:
                continue

            meta_by_identity[identity] = {
                "_found_by_thread": c.get("_found_by_thread", -1),
                "_generation": c.get("_generation", 0),
                "_lane_id": c.get("_lane_id", 0),
                "_tail64": c.get("_tail64", self._candidate_tail64(c)),
                "_nonce": c.get("_nonce", self._candidate_nonce(c)),
            }

        out: list[dict] = []

        for c in ranked_pool or []:
            try:
                cc = dict(c)
                identity = self._candidate_identity(cc)
                meta = meta_by_identity.get(identity)
                if meta:
                    cc.update(meta)
                else:
                    cc["_found_by_thread"] = -1
                    cc["_generation"] = 0
                    cc["_lane_id"] = 0
                    cc["_tail64"] = self._candidate_tail64(cc)
                    cc["_nonce"] = self._candidate_nonce(cc)
                out.append(cc)
            except Exception:
                continue

        return out

    def _update_unique_share_snapshot(
        self,
        active_states: list["_ThreadState"],
        generation: int,
        found: list[dict],
    ) -> None:
        try:
            snap = {
                "mode": "best_share_per_worker_generation",
                "threads_active": int(len(active_states)),
                "shares_found_this_round": int(len(found or [])),
                "duplicate_candidate_count": int(self._last_duplicate_candidate_count),
                "duplicate_tail64_count": int(self._last_duplicate_tail64_count),
                "worker_share_counts": dict(self._last_round_worker_share_counts),
            }

            for st in active_states:
                worker_index = int(getattr(st, "worker_index", -1))
                best_map = getattr(st, "best_share_per_generation", {}) or {}

                latest_gen = 0
                latest_tail64 = 0
                latest_nonce = 0
                latest_lane = int(getattr(st, "assigned_lane_id", 0))

                if best_map:
                    try:
                        latest_gen = max(int(k) for k in best_map.keys())
                        latest = best_map.get(latest_gen, {}) or {}
                        latest_tail64 = int(latest.get("tail64", 0)) & 0xFFFFFFFFFFFFFFFF
                        latest_nonce = int(latest.get("nonce", 0)) & 0xFFFFFFFF
                        latest_lane = int(latest.get("lane_id", latest_lane))
                    except Exception:
                        pass

                snap[f"worker_{worker_index}_best_gen"] = {
                    "generations_tracked": int(len(best_map)),
                    "latest_generation": int(latest_gen),
                    "latest_tail64": int(latest_tail64),
                    "latest_tail64_hex": f"0x{int(latest_tail64):016X}",
                    "latest_nonce": int(latest_nonce),
                    "latest_lane_id": int(latest_lane),
                }

            self._last_unique_share_snapshot = snap
            self._last_shares_found_this_round = int(len(found or []))

        except Exception:
            pass

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

                if self._hot_hash is None:
                    st.error = self._hot_hash_error or "MoneroHashLoop.dll is not loaded"
                    return -1

                if not self._hot_hash_hash_fn_ptr:
                    self._hot_hash_hash_fn_ptr = self._resolve_native_hash_fn_ptr()

                self._ensure_thread_resources(st, job)

                target64 = int(job.target64) & 0xFFFFFFFFFFFFFFFF
                keep_best = max(1, int(st.assigned_max_results))
                start_nonce = int(st.assigned_start_nonce) & 0xFFFFFFFF
                count = max(0, int(st.assigned_count))
                stride = max(1, int(getattr(st, "assigned_stride", 1)))
                stale_mask = self._stale_check_mask()

                batch = st.candidate_batch
                if batch is None:
                    batch = _CandidateBatch(
                        owner_key=f"worker-batch-{st.worker_index}",
                        max_keep_default=max(8, keep_best * 2),
                        logger=self.logger,
                    )
                    st.candidate_batch = batch

                batch.reset(
                    job_id=job_id,
                    generation=my_generation,
                    requested_keep=max(8, min(128, keep_best * 2)),
                )

                # Exact job blob copy. Native mutates nonce bytes only.
                native_blob = bytearray(job.blob)

                vm_ptr = self._resolve_native_vm_ptr(st.vm)
                if not vm_ptr:
                    st.error = "RandomX VM pointer is null"
                    return -1

                if self._stop.is_set():
                    self._native_stop_flag.value = 1

                max_candidates = self._max_candidates_for_job(job, keep_best)

                native_result = self._hot_hash.run_hot_loop(
                    hash_fn_ptr=int(self._hot_hash_hash_fn_ptr),
                    vm_ptr=int(vm_ptr),
                    blob=native_blob,
                    nonce_offset=int(job.nonce_offset),
                    start_nonce=start_nonce,
                    stride=stride,
                    count=count,
                    target64=target64,
                    stop_flag=self._native_stop_flag,
                    current_generation=self._native_generation,
                    generation=my_generation,
                    stale_mask=stale_mask,
                    max_candidates=max_candidates,
                    raise_on_error=False,
                    allow_blob_copy=False,
                )

                done = int(native_result.done_hashes or 0)
                st.done_hashes = done

                if native_result.status < 0 and native_result.status != HH_CANDIDATE_OVERFLOW:
                    err = self._hot_hash.last_error()
                    st.error = (
                        err
                        or f"MoneroHashLoop native status={native_result.status_name}"
                    )
                    return -1

                if native_result.candidates:
                    batch.merge_items(native_result.candidates)

                st.found = self._dedupe_candidates(batch.export(keep_best))

                try:
                    if getattr(st, "nonce_writer", None) is not None:
                        st.nonce_writer.clear()
                except Exception:
                    pass

                try:
                    if getattr(st, "tail64_probe", None) is not None:
                        st.tail64_probe.finish(done_hashes=done)
                except Exception:
                    pass

                try:
                    if getattr(st, "rx_lane", None) is not None:
                        st.rx_lane.finish(done_hashes=done)
                except Exception:
                    pass

                return done

            except Exception as e:
                st.error = f"{type(e).__name__}: {e}"
                return -1

        return _cb

    def _ensure_thread_resources(self, st: _ThreadState, job: "MoneroJob") -> None:
        seed_hash = bytes(job.seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        blob = bytes(job.blob or b"")
        if len(blob) < 4:
            raise ValueError("job.blob is too small")

        nonce_offset = int(job.nonce_offset)
        if nonce_offset < 0 or nonce_offset + 4 > len(blob):
            raise ValueError(
                f"nonce_offset outside blob: nonce_offset={nonce_offset} blob_len={len(blob)}"
            )

        if st.vm is None or st.last_seed != seed_hash:
            vm, epoch = self._vm_pool.acquire_for_worker(st.worker_index, seed_hash)
            st.vm = vm
            st.vm_epoch = int(epoch)
            st.last_seed = seed_hash

        blob_changed = st.last_blob != blob

        if st.blob_buf is None or len(st.blob_buf) != len(blob):
            st.blob_buf = (c_ubyte * len(blob))()
            blob_changed = True

        if blob_changed:
            memmove(st.blob_buf, blob, len(blob))
            st.last_blob = blob

        st.nonce_ptr = cast(
            byref(st.blob_buf, nonce_offset),
            POINTER(c_uint32),
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

                self._debug_track_unique_nonces(st)
                self._track_best_share_per_generation(st)

            except Exception as e:
                st.error = f"{type(e).__name__}: {e}"
            finally:
                st.busy = False
                st.done_event.set()

    def _validate_job_before_dispatch(self, job: "MoneroJob") -> str:
        try:
            seed_hash = bytes(job.seed_hash or b"")
            if not seed_hash:
                return "empty seed_hash"

            blob = bytes(job.blob or b"")
            if len(blob) < 4:
                return f"job.blob too small: {len(blob)}"

            nonce_offset = int(job.nonce_offset)
            if nonce_offset < 0 or nonce_offset + 4 > len(blob):
                return (
                    f"nonce_offset outside blob: "
                    f"nonce_offset={nonce_offset} blob_len={len(blob)}"
                )

            target64 = int(job.target64) & 0xFFFFFFFFFFFFFFFF
            if target64 <= 0:
                return "target64 must be > 0"

            return ""
        except Exception as e:
            return f"{type(e).__name__}: {e}"

    def hash_job(
        self,
        *,
        job: "MoneroJob",
        start_nonce: int,
        count: int,
        max_results: int,
    ) -> dict:
        validation_error = self._validate_job_before_dispatch(job)
        if validation_error:
            return {
                "job_id": getattr(job, "job_id", ""),
                "hashes_done": 0,
                "found": [],
                "elapsed_sec": 0.0,
                "errors": [validation_error],
            }

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

        # Critical stale-sync fix.
        # This happens before VM warmup and before any worker starts hashing.
        self._native_generation.value = int(generation) & 0xFFFFFFFFFFFFFFFF

        if not self._stop.is_set():
            self._native_stop_flag.value = 0

        self._share_diversity.begin_round(
            job_id=str(job.job_id),
            generation=int(generation),
        )

        t0 = time.perf_counter()

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

        lane_ids = self._lane_permutation(threads, int(generation))

        self._last_lane_ids = list(lane_ids)
        self._last_generation = int(generation)
        self._last_threads_used = int(threads)

        per_thread = count // threads
        remainder = count % threads

        active_states: list[_ThreadState] = []

        for i in range(threads):
            lane_id = int(lane_ids[i])
            take = per_thread + (1 if i < remainder else 0)

            if take <= 0:
                continue

            st = self._states[i]
            st.assigned_job = job
            st.assigned_generation = int(generation)
            st.assigned_lane_id = lane_id
            st.assigned_start_nonce = (int(actual_start_nonce) + lane_id) & 0xFFFFFFFF
            st.assigned_count = int(take)
            st.assigned_max_results = int(max_results)
            st.assigned_stride = int(threads)
            st.done_hashes = 0
            st.error = None

            if st.found is None:
                st.found = []
            else:
                st.found.clear()

            st.done_event.clear()
            active_states.append(st)

        for i in range(threads, len(self._states)):
            st = self._states[i]
            st.assigned_job = None
            st.assigned_generation = 0
            st.assigned_lane_id = 0
            st.assigned_start_nonce = 0
            st.assigned_count = 0
            st.assigned_max_results = 0
            st.assigned_stride = 1
            st.done_hashes = 0
            st.error = None

            if st.found is not None:
                st.found.clear()

        for st in active_states:
            st.start_event.set()

        for st in active_states:
            st.done_event.wait()

        hashes_done = 0
        errors: list[str] = []

        round_batch = self._round_candidate_batch
        round_batch.reset(
            job_id=str(job.job_id),
            generation=int(generation),
            requested_keep=max(max_results * 8, 256),
        )

        for st in active_states:
            hashes_done += int(st.done_hashes or 0)

            if st.found:
                round_batch.merge_items(st.found)

            if st.error:
                errors.append(
                    f"worker[{st.worker_index}] "
                    f"lane={getattr(st, 'assigned_lane_id', 0)} "
                    f"start_nonce={int(getattr(st, 'assigned_start_nonce', 0)) & 0xFFFFFFFF} "
                    f"stride={int(getattr(st, 'assigned_stride', 1))} "
                    f"{st.error}"
                )

        annotated = self._collect_annotated_worker_candidates(
            active_states=active_states,
            generation=int(generation),
        )

        if annotated:
            # First balance the broad native outputs by worker.
            balanced_annotated = self._round_robin_annotated_candidates(
                annotated,
                limit=max(max_results * 16, 256),
            )
            pre_rank = self._strip_candidate_debug_fields(balanced_annotated)
        else:
            pre_rank = round_batch.export(max(max_results * 16, 256))

        pre_rank = self._dedupe_candidates(pre_rank)

        ranked_pool = self._selector.rank(
            pre_rank,
            max(max_results * 8, 64),
        )

        ranked_pool = self._dedupe_candidates(ranked_pool)

        if annotated and ranked_pool:
            # Reattach worker IDs after ranking, then do final worker-balanced order.
            ranked_annotated = self._reapply_worker_metadata(ranked_pool, annotated)
            ranked_balanced = self._round_robin_annotated_candidates(
                ranked_annotated,
                limit=max(max_results * 8, 64),
            )
            final_pool = self._strip_candidate_debug_fields(ranked_balanced)
        else:
            final_pool = ranked_pool

        final_pool = self._dedupe_candidates(final_pool)

        found = self._share_diversity.pick(
            job_id=str(job.job_id),
            generation=int(generation),
            candidates=final_pool,
            max_results=max_results,
        )

        found = self._dedupe_candidates(found)

        self._update_unique_share_snapshot(
            active_states=active_states,
            generation=int(generation),
            found=found,
        )

        return {
            "job_id": job.job_id,
            "hashes_done": hashes_done,
            "found": found,
            "elapsed_sec": max(0.0, time.perf_counter() - t0),
            "errors": errors,
        }

    def snapshot_execution(self) -> dict:
        snap = self._exec.snapshot()

        try:
            snap["monero_hash_loop"] = {
                "loaded": self._hot_hash is not None,
                "dll_path": "" if self._hot_hash is None else str(self._hot_hash.dll_path),
                "prefix": "" if self._hot_hash is None else str(self._hot_hash.prefix),
                "version": 0 if self._hot_hash is None else int(self._hot_hash.version()),
                "hash_fn_ptr": int(self._hot_hash_hash_fn_ptr or 0),
                "hash_fn_ptr_hex": f"0x{int(self._hot_hash_hash_fn_ptr or 0):x}",
                "error": self._hot_hash_error,
                "native_max_candidates_cap": int(self._native_max_candidates_cap),
                "current_generation": int(self._native_generation.value),
                "stop_flag": int(self._native_stop_flag.value),
            }

            snap["nonce_diversity"] = {
                "mode": "unique_per_generation_lane_permutation",
                "lane_permutation_variant": str(self._lane_permutation_variant),
                "unsafe_blob_xor_enabled": bool(self._unsafe_blob_xor_enabled),
                "debug_unique_nonces": bool(self._debug_unique_nonces),
                "threads": int(self.threads),
                "batch_size": int(self.batch_size),
                "last_threads_used": int(self._last_threads_used),
                "last_generation": int(self._last_generation),
                "last_lane_ids": list(self._last_lane_ids),
                "last_lane_count": len(self._last_lane_ids),
                "last_lane_unique": len(set(self._last_lane_ids)) == len(self._last_lane_ids),
            }

            share_snap = dict(self._last_unique_share_snapshot or {})
            share_snap.setdefault("mode", "best_share_per_worker_generation")
            share_snap.setdefault("threads_active", int(self._last_threads_used))
            share_snap.setdefault("shares_found_this_round", int(self._last_shares_found_this_round))
            share_snap.setdefault("duplicate_candidate_count", int(self._last_duplicate_candidate_count))
            share_snap.setdefault("duplicate_tail64_count", int(self._last_duplicate_tail64_count))
            share_snap.setdefault("worker_share_counts", dict(self._last_round_worker_share_counts))

            for st in self._states:
                worker_index = int(getattr(st, "worker_index", -1))
                best_map = getattr(st, "best_share_per_generation", {}) or {}

                latest_gen = 0
                latest_tail64 = 0
                latest_nonce = 0
                latest_lane = int(getattr(st, "assigned_lane_id", 0))

                if best_map:
                    try:
                        latest_gen = max(int(k) for k in best_map.keys())
                        latest = best_map.get(latest_gen, {}) or {}
                        latest_tail64 = int(latest.get("tail64", 0)) & 0xFFFFFFFFFFFFFFFF
                        latest_nonce = int(latest.get("nonce", 0)) & 0xFFFFFFFF
                        latest_lane = int(latest.get("lane_id", latest_lane))
                    except Exception:
                        pass

                share_snap[f"worker_{worker_index}_best_gen"] = {
                    "generations_tracked": int(len(best_map)),
                    "latest_generation": int(latest_gen),
                    "latest_tail64": int(latest_tail64),
                    "latest_tail64_hex": f"0x{int(latest_tail64):016X}",
                    "latest_nonce": int(latest_nonce),
                    "latest_lane_id": int(latest_lane),
                }

            snap["unique_shares_per_thread"] = share_snap

        except Exception:
            pass

        return snap

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
        return (
            -int(item["tail64"]),
            float(item["share_diff_est"]),
            -int(item["nonce_u32"]),
        )

    def _keep_local_best(
        self,
        heap: list[tuple[tuple[int, float, int], dict]],
        item: dict,
        keep: int,
    ) -> None:
        keep = max(1, int(keep))
        entry = (self._candidate_heap_key(item), item)

        if len(heap) < keep:
            heapq.heappush(heap, entry)
            return

        if entry[0] > heap[0][0]:
            heapq.heapreplace(heap, entry)

    def stop(self) -> None:
        self._stop.set()
        self._native_stop_flag.value = 1

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

        try:
            if self._hot_hash is not None:
                self._hot_hash.close()
        except Exception:
            pass

        for st in self._states:
            st.vm = None
            st.vm_epoch = 0
            st.blob_buf = None
            st.nonce_ptr = None
            st.out_buf = None
            st.last_seed = b""
            st.last_blob = b""

            st.assigned_job = None
            st.assigned_generation = 0
            st.assigned_lane_id = 0
            st.assigned_start_nonce = 0
            st.assigned_count = 0
            st.assigned_max_results = 0
            st.assigned_stride = 1

            if getattr(st, "nonce_writer", None) is not None:
                try:
                    st.nonce_writer.clear()
                except Exception:
                    pass
            st.nonce_writer = None

            if getattr(st, "tail64_probe", None) is not None:
                try:
                    st.tail64_probe.clear()
                except Exception:
                    pass
            st.tail64_probe = None

            if getattr(st, "rx_lane", None) is not None:
                try:
                    st.rx_lane.clear()
                except Exception:
                    pass
            st.rx_lane = None

            if getattr(st, "candidate_batch", None) is not None:
                try:
                    st.candidate_batch.reset(
                        job_id="",
                        generation=0,
                        requested_keep=max(8, self.batch_size // 64),
                    )
                except Exception:
                    pass

            if getattr(st, "unique_nonce_tracker", None) is not None:
                try:
                    st.unique_nonce_tracker.nonce_seen = set()
                    st.unique_nonce_tracker.logged_count = 0
                    st.unique_nonce_tracker.generation = 0
                except Exception:
                    pass

            if getattr(st, "best_share_per_generation", None) is not None:
                try:
                    st.best_share_per_generation.clear()
                except Exception:
                    pass