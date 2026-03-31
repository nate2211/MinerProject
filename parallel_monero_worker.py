from __future__ import annotations

import ctypes
import heapq
import os
import sys
import threading
import time
from ctypes import (
    POINTER,
    byref,
    cast,
    memmove,
    c_bool,
    c_char_p,
    c_double,
    c_int,
    c_uint32,
    c_ubyte,
    c_void_p,
)
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Any

from monero_job import MoneroJob
from python_jit import PythonJIT
from python_runtime import PYR_TASK_ECHO, PythonRuntime, PythonRuntimeError
from python_usage import PythonUsage
from randomx_ctypes import RandomX


@dataclass(frozen=True)
class WorkerShare:
    job_id: str
    nonce_u32: int
    result32: bytes

    @property
    def nonce_hex(self) -> str:
        return int(self.nonce_u32).to_bytes(4, "little", signed=False).hex()

    @property
    def result_hex(self) -> str:
        return (self.result32 or b"").hex()


@dataclass(frozen=True)
class WorkerStats:
    hashes_done: int
    shares_found: int
    elapsed_sec: float


class _ThreadState(threading.local):
    def __init__(self) -> None:
        super().__init__()
        self.seed_hash: bytes = b""
        self.vm = None
        self.blob_buf = None
        self.nonce_ptr = None
        self.out_buf = None


class ParallelPythonBridge:
    PythonCallback = ctypes.CFUNCTYPE(None)
    IntCallback = ctypes.CFUNCTYPE(None, POINTER(c_int))
    BoolCallback = ctypes.CFUNCTYPE(None, POINTER(c_bool))
    DoubleCallback = ctypes.CFUNCTYPE(None, POINTER(c_double))
    StringCallback = ctypes.CFUNCTYPE(None, c_char_p, c_int)

    class PythonCallDescriptor(ctypes.Structure):
        _fields_ = [
            ("FuncPtr", c_void_p),
            ("ResultPtr", c_void_p),
            ("BufferSize", c_int),
            ("Type", c_int),
        ]

    TYPE_VOID = 0
    TYPE_INT = 1
    TYPE_BOOL = 2
    TYPE_DOUBLE = 3
    TYPE_STRING = 4

    def __init__(self, logger: Optional[Callable[[str], None]] = None, dll_path: str = "", python_runtime = None) -> None:
        self.logger = logger or (lambda s: None)
        self.python_runtime = python_runtime
        self.dll_path = self._resolve_dll_path(dll_path)
        self.dll = None
        self.available = False
        self._load()

    def _resolve_dll_path(self, dll_path: str) -> str:
        candidates: list[Path] = []
        if dll_path:
            candidates.append(Path(dll_path))

        env = os.environ.get("PARALLEL_PYTHON_DLL", "").strip()
        if env:
            candidates.append(Path(env))

        base_paths: list[Path] = []
        try:
            base_paths.append(Path(__file__).resolve().parent)
        except Exception:
            pass
        try:
            base_paths.append(Path.cwd())
        except Exception:
            pass
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            try:
                base_paths.append(Path(meipass))
            except Exception:
                pass

        names = [
            "ParallelPython.dll",
            "parallelpython.dll",
            "tools/ParallelPython.dll",
            "tools/parallelpython.dll",
        ]
        for base in base_paths:
            for name in names:
                candidates.append(base / name)

        seen = set()
        uniq: list[Path] = []
        for p in candidates:
            key = str(p).lower()
            if key not in seen:
                seen.add(key)
                uniq.append(p)

        for p in uniq:
            if p.exists():
                return str(p)

        return str(uniq[0]) if uniq else ""

    def _load(self) -> None:
        if not self.dll_path or not os.path.exists(self.dll_path):
            self.logger(f"[ParallelPythonBridge] DLL not found: {self.dll_path}")
            self.available = False
            return

        try:
            self.dll = ctypes.cdll.LoadLibrary(self.dll_path)

            self.dll.invoke_python_callback.argtypes = [c_void_p]
            self.dll.invoke_python_callback.restype = None

            self.dll.invoke_python_int.argtypes = [c_void_p, POINTER(c_int)]
            self.dll.invoke_python_int.restype = None

            self.dll.invoke_python_bool.argtypes = [c_void_p, POINTER(c_bool)]
            self.dll.invoke_python_bool.restype = None

            self.dll.invoke_python_double.argtypes = [c_void_p, POINTER(c_double)]
            self.dll.invoke_python_double.restype = None

            self.dll.invoke_python_string.argtypes = [c_void_p, c_char_p, c_int]
            self.dll.invoke_python_string.restype = None

            # FIX: use the real descriptor pointer type, not plain c_void_p
            self.dll.invoke_all_parallel.argtypes = [POINTER(self.PythonCallDescriptor), c_int]
            self.dll.invoke_all_parallel.restype = None

            self.available = True
            self.logger(f"[ParallelPythonBridge] Loaded DLL: {self.dll_path}")
        except Exception as e:
            self.available = False
            self.dll = None
            self.logger(f"[ParallelPythonBridge] Failed to load DLL: {e}")

    def make_void_callback(self, func: Callable[[], None]):
        if isinstance(func, self.PythonCallback):
            return func

        if not callable(func):
            raise TypeError(f"make_void_callback expected a callable, got {type(func)!r}")

        def _wrapped():
            rt = self.python_runtime
            entered = False

            try:
                if rt is not None and hasattr(rt, "_enter_parallelpython_callback"):
                    rt._enter_parallelpython_callback()
                    entered = True

                func()
            finally:
                if entered and rt is not None and hasattr(rt, "_exit_parallelpython_callback"):
                    rt._exit_parallelpython_callback()

        return self.PythonCallback(_wrapped)

    def make_int_callback(self, func: Callable[[], int]):
        def cb(ptr):
            try:
                ptr.contents.value = int(func())
            except Exception:
                ptr.contents.value = 0
        return self.IntCallback(cb)

    def make_bool_callback(self, func: Callable[[], bool]):
        def cb(ptr):
            try:
                ptr.contents.value = bool(func())
            except Exception:
                ptr.contents.value = False
        return self.BoolCallback(cb)

    def make_double_callback(self, func: Callable[[], float]):
        def cb(ptr):
            try:
                ptr.contents.value = float(func())
            except Exception:
                ptr.contents.value = 0.0
        return self.DoubleCallback(cb)

    def make_string_callback(self, func: Callable[[], str], buffer_size: int = 1024):
        def cb(buf, size):
            try:
                data = str(func()).encode("utf-8", errors="replace")
            except Exception:
                data = b""

            size_i = max(0, int(size))
            n = min(len(data), max(0, size_i - 1))

            if n > 0:
                ctypes.memmove(buf, data, n)

            if size_i > 0:
                base_ptr = cast(buf, c_void_p).value
                if base_ptr:
                    ctypes.memset(c_void_p(base_ptr + n), 0, 1)

        return self.StringCallback(cb), ctypes.create_string_buffer(buffer_size)

    def invoke_all_void(self, callbacks: list) -> None:
        if not callbacks:
            return

        normalized = [self.make_void_callback(cb) for cb in callbacks]

        if not self.available or self.dll is None:
            for cb in normalized:
                cb()
            return

        descs = [
            self.PythonCallDescriptor(
                c_void_p(cast(cb, c_void_p).value),
                c_void_p(),
                0,
                self.TYPE_VOID,
            )
            for cb in normalized
        ]

        arr_t = self.PythonCallDescriptor * len(descs)
        arr = arr_t(*descs)
        self.dll.invoke_all_parallel(arr, len(descs))

    def invoke_int(self, cb) -> int:
        if not self.available or self.dll is None:
            res = c_int()
            cb(byref(res))
            return int(res.value)
        res = c_int()
        self.dll.invoke_python_int(c_void_p(cast(cb, c_void_p).value), byref(res))
        return int(res.value)

    def invoke_bool(self, cb) -> bool:
        if not self.available or self.dll is None:
            res = c_bool()
            cb(byref(res))
            return bool(res.value)
        res = c_bool()
        self.dll.invoke_python_bool(c_void_p(cast(cb, c_void_p).value), byref(res))
        return bool(res.value)

    def invoke_double(self, cb) -> float:
        if not self.available or self.dll is None:
            res = c_double()
            cb(byref(res))
            return float(res.value)
        res = c_double()
        self.dll.invoke_python_double(c_void_p(cast(cb, c_void_p).value), byref(res))
        return float(res.value)

    def invoke_string(self, cb, buffer_size: int = 1024) -> str:
        buf = ctypes.create_string_buffer(buffer_size)
        if not self.available or self.dll is None:
            cb(buf, buffer_size)
            return buf.value.decode("utf-8", errors="replace")
        self.dll.invoke_python_string(c_void_p(cast(cb, c_void_p).value), buf, buffer_size)
        return buf.value.decode("utf-8", errors="replace")



@dataclass
class _VMState:
    seed_hash: bytes = b""
    vm: Any = None
    blob_buf: Any = None
    nonce_ptr: Any = None
    out_buf: Any = None
@dataclass
class _LaneState:
    worker_index: int
    vm: Any = None
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

    launch_callback: Optional[Callable[[], None]] = None
    launch_mode: str = "direct"
class ParallelMoneroWorker:
    """
    JITWorker-style ParallelMoneroWorker while keeping the same public API.

    Key design:
      - persistent worker threads
      - one reusable RandomX VM per worker lane
      - batch/age strategy similar to JITWorker
      - PythonRuntime + PythonUsage + ParallelPythonBridge are still used,
        but only for launch/fan-out, not the actual hot hashing loop
    """

    def __init__(
        self,
        *,
        threads: int = 1,
        logger: Optional[Callable[[str], None]] = None,
        randomx: Optional[RandomX] = None,
        dll_path: str = "",
        batch_size: int = 1024,
        python_runtime: Optional[PythonRuntime] = None,
        python_usage: Optional[PythonUsage] = None,
        python_jit: Optional[PythonJIT] = None,
    ) -> None:
        self.logger = logger or (lambda s: None)
        self.threads = max(1, int(threads))
        self.batch_size = max(1, int(batch_size))
        self.rx = randomx or RandomX(self.logger)
        self.bridge = ParallelPythonBridge(
            logger=self.logger,
            dll_path=dll_path,
            python_runtime=python_runtime,
        )

        self.python_runtime = python_runtime
        self.python_usage = python_usage
        self.python_jit = python_jit

        self._seed_lock = threading.RLock()
        self._job_lock = threading.RLock()
        self._hash_job_lock = threading.Lock()
        self._stop = threading.Event()

        self._prepared_seed: bytes = b""
        self._dispatch_generation = 0
        self._current_job_id = ""
        self._current_job_started_at = 0.0

        self._tls = _ThreadState()
        self._lanes: list[_LaneState] = []
        self._threads: list[threading.Thread] = []
        self._lane_by_ident: dict[int, _LaneState] = {}

        self._last_hashes_done = 0
        self._last_job_id = ""
        self._last_elapsed = 0.0

        self._bootstrap_workers()
        self._preflight_control_plane()

    def stop(self) -> None:
        self._stop.set()

    def reset_stop(self) -> None:
        self._stop.clear()

    def close(self) -> None:
        self._stop.set()

        for lane in self._lanes:
            try:
                if lane.start_event is not None:
                    lane.start_event.set()
            except Exception:
                pass

        for t in self._threads:
            try:
                t.join(timeout=1.5)
            except Exception:
                pass

        for lane in self._lanes:
            self._destroy_lane_vm(lane)

    def ensure_seed(self, seed_hash: bytes) -> None:
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        with self._seed_lock:
            if seed_hash == self._prepared_seed:
                return
            self.rx.ensure_seed(seed_hash)
            self._prepared_seed = seed_hash

    def _bootstrap_workers(self) -> None:
        for i in range(self.threads):
            lane = _LaneState(
                worker_index=i,
                out_buf=(c_ubyte * 32)(),
                found=[],
                start_event=threading.Event(),
                done_event=threading.Event(),
                stop_event=self._stop,
            )
            lane.launch_callback, lane.launch_mode = self._make_launch_callback(lane)

            t = threading.Thread(
                target=self._thread_main,
                args=(lane,),
                name=f"ParallelMoneroWorker-{i}",
                daemon=True,
            )
            self._lanes.append(lane)
            self._threads.append(t)
            t.start()

        mode_counts: dict[str, int] = {}
        for lane in self._lanes:
            mode_counts[lane.launch_mode] = mode_counts.get(lane.launch_mode, 0) + 1

        self.logger(
            f"[ParallelMoneroWorker] initialized: "
            f"threads={self.threads} "
            f"batch_size={self.batch_size} "
            f"bridge_available={self.bridge.available} "
            f"launch_modes={mode_counts}"
        )

    def _preflight_control_plane(self) -> None:
        callbacks = [
            lane.launch_callback
            for lane in self._lanes[: min(4, len(self._lanes))]
            if callable(lane.launch_callback)
        ]
        if not callbacks:
            return

        try:
            self.bridge.invoke_all_void(callbacks)
            self.logger(
                f"[ParallelMoneroWorker] control-plane preflight complete "
                f"(callbacks={len(callbacks)})"
            )
        except Exception as e:
            self.logger(
                f"[ParallelMoneroWorker] control-plane preflight failed: "
                f"{type(e).__name__}: {e}"
            )

    def _make_launch_callback(self, lane: _LaneState) -> tuple[Callable[[], None], str]:
        def _start_lane() -> None:
            if lane.start_event is not None:
                lane.start_event.set()

        wrapped: Callable[[], None] = _start_lane
        mode_parts: list[str] = []

        if self.python_runtime is not None:
            try:
                def _factory(cb=_start_lane):
                    return cb

                rt_cb = self.python_runtime.wrap_parallel_void_factory(
                    _factory,
                    timeout_ms=0xFFFFFFFF,
                    gate_task=PYR_TASK_ECHO,
                    gate_payload=f"__pmw_lane__:{lane.worker_index}".encode("utf-8"),
                    name=f"pmw_lane_{lane.worker_index}",
                )
                if callable(rt_cb):
                    wrapped = rt_cb
                    mode_parts.append("runtime")
            except Exception as e:
                self.logger(
                    f"[ParallelMoneroWorker] worker[{lane.worker_index}] "
                    f"PythonRuntime wrap failed; using direct start: "
                    f"{type(e).__name__}: {e}"
                )

        if self.python_usage is not None:
            # Keep PythonUsage in the fan-out path, not the hashing path.
            # Only wrap a subset of lanes to avoid turning launch into a bottleneck.
            if lane.worker_index < min(2, self.threads):
                try:
                    usage_cb = self.python_usage.wrap_function(wrapped)
                    if callable(usage_cb):
                        wrapped = usage_cb
                        mode_parts.append("usage")
                except Exception as e:
                    self.logger(
                        f"[ParallelMoneroWorker] worker[{lane.worker_index}] "
                        f"PythonUsage wrap failed; keeping prior mode: "
                        f"{type(e).__name__}: {e}"
                    )

        mode = "+".join(mode_parts) if mode_parts else "direct"
        return wrapped, mode

    def _thread_main(self, lane: _LaneState) -> None:
        ident = threading.get_ident()
        with self._job_lock:
            self._lane_by_ident[ident] = lane

        try:
            while True:
                lane.start_event.wait()
                lane.start_event.clear()

                if self._stop.is_set():
                    break

                lane.done_event.clear()
                lane.busy = True
                try:
                    self._run_lane(lane)
                finally:
                    lane.busy = False
                    lane.done_event.set()
        finally:
            with self._job_lock:
                self._lane_by_ident.pop(ident, None)

    def _current_job_age_ms(self) -> float:
        with self._job_lock:
            if self._current_job_started_at <= 0.0:
                return 0.0
            return max(0.0, (time.perf_counter() - self._current_job_started_at) * 1000.0)

    def _effective_count(self, requested_count: int) -> int:
        count = max(0, int(requested_count))
        if count <= 0:
            return 0

        age_ms = self._current_job_age_ms()

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
        age_ms = self._current_job_age_ms()
        if age_ms < 150.0:
            return 63
        if age_ms < 400.0:
            return 31
        if age_ms < 900.0:
            return 15
        return 7

    def _is_current(self, job_id: str, generation: int) -> bool:
        with self._job_lock:
            return (
                str(job_id) == self._current_job_id
                and int(generation) == int(self._dispatch_generation)
            )

    def _destroy_lane_vm(self, lane: _LaneState) -> None:
        if lane.vm is not None:
            try:
                self.rx.destroy_vm(lane.vm)
            except Exception:
                pass
        lane.vm = None
        lane.blob_buf = None
        lane.nonce_ptr = None
        lane.out_buf = None
        lane.last_seed = b""
        lane.last_blob = b""

    def _prepare_lane_resources(self, lane: _LaneState, job: MoneroJob) -> None:
        blob = bytes(job.blob or b"")
        seed_hash = bytes(job.seed_hash or b"")
        nonce_offset = int(job.nonce_offset)

        if not blob:
            raise ValueError("job.blob is empty")
        if not seed_hash:
            raise ValueError("job.seed_hash is empty")
        if nonce_offset < 0 or (nonce_offset + 4) > len(blob):
            raise ValueError(
                f"invalid nonce_offset {nonce_offset} for blob length {len(blob)}"
            )

        self.ensure_seed(seed_hash)

        if lane.vm is None or lane.last_seed != seed_hash:
            if lane.vm is not None:
                try:
                    self.rx.destroy_vm(lane.vm)
                except Exception:
                    pass
                lane.vm = None

            new_vm = self.rx.create_vm()
            if new_vm is None:
                raise RuntimeError("RandomX create_vm() returned None")

            lane.vm = new_vm
            lane.last_seed = seed_hash

        if lane.blob_buf is None or len(lane.blob_buf) != len(blob):
            lane.blob_buf = (c_ubyte * len(blob))()
            lane.last_blob = b""

        if lane.out_buf is None:
            lane.out_buf = (c_ubyte * 32)()

        if lane.last_blob != blob:
            memmove(lane.blob_buf, blob, len(blob))
            lane.last_blob = blob

        lane.nonce_ptr = cast(
            byref(lane.blob_buf, nonce_offset),
            POINTER(c_uint32),
        )
        _ = lane.nonce_ptr[0]

        # Mirror for compatibility with older helper flow.
        self._tls.seed_hash = lane.last_seed
        self._tls.vm = lane.vm
        self._tls.blob_buf = lane.blob_buf
        self._tls.nonce_ptr = lane.nonce_ptr
        self._tls.out_buf = lane.out_buf

    @staticmethod
    def _candidate_sort_key(item: dict) -> tuple[int, float, int]:
        return (
            int(item["tail64"]),
            -float(item["share_diff_est"]),
            int(item["nonce_u32"]),
        )

    @staticmethod
    def _candidate_heap_key(item: dict) -> tuple[int, float, int]:
        # heap root = worst kept candidate
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

    def _rank_found(self, gathered: list[dict], max_results: int) -> list[dict]:
        if max_results <= 0 or not gathered:
            return []

        best_by_key: dict[tuple[int, str], dict] = {}
        for item in gathered:
            key = (int(item["nonce_u32"]), str(item["hash_hex"]))
            prev = best_by_key.get(key)
            if prev is None or self._candidate_sort_key(item) < self._candidate_sort_key(prev):
                best_by_key[key] = item

        ranked = sorted(best_by_key.values(), key=self._candidate_sort_key)
        return ranked[:max_results]

    def _run_lane_once(self, lane: _LaneState) -> None:
        lane.error = None
        lane.done_hashes = 0
        if lane.found is None:
            lane.found = []
        else:
            lane.found.clear()

        job = lane.assigned_job
        if job is None:
            return

        job_id = str(job.job_id)
        generation = int(lane.assigned_generation or 0)
        if generation <= 0:
            return

        if not self._is_current(job_id, generation):
            return

        self._prepare_lane_resources(lane, job)

        rx_hash_into = self.rx.hash_into
        target64 = int(job.target64) & 0xFFFFFFFFFFFFFFFF

        keep_best = max(0, int(lane.assigned_max_results))
        start_nonce = int(lane.assigned_start_nonce) & 0xFFFFFFFF
        count = max(0, int(lane.assigned_count))

        stop_flag = self._stop
        nonce_ptr = lane.nonce_ptr
        blob_buf = lane.blob_buf
        out_buf = lane.out_buf
        stale_mask = self._stale_check_mask()

        done = 0
        local_heap: list[tuple[tuple[int, float, int], dict]] = []

        for i in range(count):
            if stop_flag.is_set():
                break

            if (i & stale_mask) == 0 and not self._is_current(job_id, generation):
                break

            nonce_u32 = (start_nonce + i) & 0xFFFFFFFF
            nonce_ptr[0] = nonce_u32
            rx_hash_into(lane.vm, blob_buf, out_buf)
            done += 1

            if keep_best <= 0:
                continue

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

        lane.done_hashes = done
        lane.found = [
            item for _, item in sorted(local_heap, key=lambda x: self._candidate_sort_key(x[1]))
        ] if local_heap else []

    def _run_lane(self, lane: _LaneState) -> None:
        try:
            self._run_lane_once(lane)
            return
        except Exception:
            # Rebuild the VM once and retry, similar to a self-heal path.
            self._destroy_lane_vm(lane)

        try:
            self._run_lane_once(lane)
        except Exception as e:
            lane.error = f"{type(e).__name__}: {e}"
            lane.done_hashes = 0
            lane.found = []

    def _get_current_lane(self) -> _LaneState:
        ident = threading.get_ident()
        with self._job_lock:
            lane = self._lane_by_ident.get(ident)
        if lane is not None:
            return lane

        lane = getattr(self._tls, "compat_lane", None)
        if lane is None:
            lane = _LaneState(
                worker_index=-1,
                out_buf=(c_ubyte * 32)(),
                found=[],
            )
            self._tls.compat_lane = lane
        return lane

    def _ensure_thread_vm(self, job: MoneroJob) -> None:
        lane = self._get_current_lane()
        self._prepare_lane_resources(lane, job)

    def _hash_range(
        self,
        *,
        job: MoneroJob,
        start_nonce: int,
        count: int,
        max_results: int,
        out_found: list,
        out_hashes: list,
        out_errors: list,
        out_lock: threading.Lock,
    ) -> None:
        try:
            lane = self._get_current_lane()
            self._prepare_lane_resources(lane, job)

            rx_hash_into = self.rx.hash_into
            target64 = int(job.target64) & 0xFFFFFFFFFFFFFFFF

            local_done = 0
            local_heap: list[tuple[tuple[int, float, int], dict]] = []
            keep_best = max(0, int(max_results))

            for i in range(max(0, int(count))):
                if self._stop.is_set():
                    break

                nonce_u32 = (int(start_nonce) + i) & 0xFFFFFFFF
                lane.nonce_ptr[0] = nonce_u32
                rx_hash_into(lane.vm, lane.blob_buf, lane.out_buf)
                local_done += 1

                if keep_best <= 0:
                    continue

                tail64 = int.from_bytes(bytes(lane.out_buf[24:32]), "little", signed=False)
                if tail64 < target64:
                    h32 = bytes(lane.out_buf)
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

            local_found = [
                item for _, item in sorted(local_heap, key=lambda x: self._candidate_sort_key(x[1]))
            ]

            with out_lock:
                out_hashes.append(local_done)
                if local_found:
                    out_found.extend(local_found)

        except Exception as e:
            with out_lock:
                out_errors.append(str(e))

    def hash_job(
        self,
        *,
        job: MoneroJob,
        start_nonce: int,
        count: int,
        max_results: int,
    ) -> dict:
        if count <= 0:
            return {
                "job_id": job.job_id,
                "hashes_done": 0,
                "found": [],
                "elapsed_sec": 0.0,
            }

        with self._hash_job_lock:
            t0 = time.perf_counter()
            self.reset_stop()

            with self._job_lock:
                now = time.perf_counter()
                if str(job.job_id) != self._current_job_id:
                    self._current_job_id = str(job.job_id)
                    self._current_job_started_at = now
                elif self._current_job_started_at <= 0.0:
                    self._current_job_started_at = now

                self._dispatch_generation += 1
                generation = self._dispatch_generation

            try:
                setattr(job, "generation", int(generation))
            except Exception:
                pass

            self.ensure_seed(job.seed_hash)

            count = self._effective_count(count)
            if count <= 0:
                return {
                    "job_id": job.job_id,
                    "hashes_done": 0,
                    "found": [],
                    "elapsed_sec": max(0.0, time.perf_counter() - t0),
                }

            threads = min(self.threads, count)
            per_thread = count // threads
            remainder = count % threads
            nonce_cursor = int(start_nonce) & 0xFFFFFFFF

            active_lanes: list[_LaneState] = []

            per_thread_candidate_budget = 0
            if max_results > 0:
                per_thread_candidate_budget = max(
                    4,
                    min(128, max(1, int(max_results)) * 4),
                )

            for i in range(threads):
                take = per_thread + (1 if i < remainder else 0)
                if take <= 0:
                    continue

                lane = self._lanes[i]
                lane.assigned_job = job
                lane.assigned_generation = generation
                lane.assigned_start_nonce = nonce_cursor
                lane.assigned_count = take
                lane.assigned_max_results = per_thread_candidate_budget
                lane.done_hashes = 0
                lane.error = None

                if lane.found is None:
                    lane.found = []
                else:
                    lane.found.clear()

                lane.done_event.clear()

                nonce_cursor = (nonce_cursor + take) & 0xFFFFFFFF
                active_lanes.append(lane)

            launch_callbacks = [
                lane.launch_callback
                for lane in active_lanes
                if callable(lane.launch_callback)
            ]

            try:
                if launch_callbacks:
                    self.bridge.invoke_all_void(launch_callbacks)
                else:
                    for lane in active_lanes:
                        lane.start_event.set()
            except Exception:
                for lane in active_lanes:
                    lane.start_event.set()

            for lane in active_lanes:
                lane.done_event.wait()

            hashes_done = 0
            gathered: list[dict] = []
            errors: list[str] = []

            for lane in active_lanes:
                hashes_done += int(lane.done_hashes or 0)
                if lane.found:
                    gathered.extend(lane.found)
                if lane.error:
                    errors.append(f"worker[{lane.worker_index}] {lane.error}")

            found = self._rank_found(gathered, max_results=max_results)
            elapsed = time.perf_counter() - t0

            self._last_hashes_done = hashes_done
            self._last_job_id = str(job.job_id)
            self._last_elapsed = elapsed

            if errors:
                self.logger(f"[ParallelMoneroWorker] hashing errors: {' | '.join(errors[:4])}")

            return {
                "job_id": job.job_id,
                "hashes_done": hashes_done,
                "found": found,
                "elapsed_sec": elapsed,
            }

    def get_last_hashes_done(self) -> int:
        return int(self._last_hashes_done)

    def get_last_elapsed(self) -> float:
        return float(self._last_elapsed)

    def get_last_job_id(self) -> str:
        return str(self._last_job_id)