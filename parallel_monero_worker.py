from __future__ import annotations

import ctypes
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

class ParallelMoneroWorker:
    """
    Safe hybrid design:
      - actual Monero hashing stays local in _hash_range() using RandomX
      - ParallelPython is used only for callback fan-out
      - PythonRuntime is used only as a lightweight control-plane health check

    Why:
      - the uploaded PythonRuntime wrapper/DLL do not yet implement a real native
        Monero task for PYR_TASK_USER_BASE + N
      - the old runtime branch used wait_result()/release_result(), which do not
        match the current wrapper API
      - keeping PythonRuntime out of the hot hashing path avoids the access-
        violation-prone teardown pattern you were hitting
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
        self.bridge = ParallelPythonBridge(logger=self.logger, dll_path=dll_path, python_runtime=python_runtime)

        self._vm_cv = threading.Condition()
        self._vm_pool: list[_VMState] = []
        self._vm_total_created = 0
        self._vm_limit = self.threads
        self._seed_lock = threading.RLock()
        self._prepared_seed: bytes = b""
        self._stop = threading.Event()

        self._last_hashes_done = 0
        self._last_job_id = ""
        self._last_elapsed = 0.0

        self.python_runtime = python_runtime
        self.python_usage = python_usage
        self.python_jit = python_jit
    def stop(self) -> None:
        self._stop.set()

    def reset_stop(self) -> None:
        self._stop.clear()

    def close(self) -> None:
        self._stop.set()

        pooled = []
        with self._vm_cv:
            if self._vm_pool:
                pooled = list(self._vm_pool)
                self._vm_pool.clear()

            if pooled:
                self._vm_total_created -= len(pooled)
                if self._vm_total_created < 0:
                    self._vm_total_created = 0

            self._vm_cv.notify_all()

        for st in pooled:
            if st.vm is not None:
                try:
                    self.rx.destroy_vm(st.vm)
                except Exception:
                    pass
            st.vm = None
            st.seed_hash = b""
            st.blob_buf = None
            st.nonce_ptr = None
            st.out_buf = None

        # Intentionally do not close self.python_runtime here.
        # The owner should manage PythonRuntime lifecycle so we do not race
        # other components or tear it down while someone else is using it.

    def ensure_seed(self, seed_hash: bytes) -> None:
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        with self._seed_lock:
            if seed_hash == self._prepared_seed:
                return
            self.rx.ensure_seed(seed_hash)
            self._prepared_seed = seed_hash

    def _ensure_thread_vm(self, job: MoneroJob) -> None:
        """
        Bounded VM checkout + prepare, while preserving the existing contract:
            self._ensure_thread_vm(job)
            st = self._tls

        Uses the already-existing:
            self._vm_cv
            self._vm_pool
            self._vm_total_created
            self._vm_limit
        """
        if job is None:
            raise ValueError("job is required")

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

        tls = getattr(self, "_tls", None)
        if tls is None:
            tls = threading.local()
            self._tls = tls

        if not hasattr(tls, "seed_hash"):
            tls.seed_hash = b""
        if not hasattr(tls, "vm"):
            tls.vm = None
        if not hasattr(tls, "blob_buf"):
            tls.blob_buf = None
        if not hasattr(tls, "nonce_ptr"):
            tls.nonce_ptr = None
        if not hasattr(tls, "out_buf"):
            tls.out_buf = None
        if not hasattr(tls, "_checked_out_vm_state"):
            tls._checked_out_vm_state = None

        # Already checked out for this call path
        st = tls._checked_out_vm_state
        if st is None:
            created_slot = False
            with self._vm_cv:
                while True:
                    if self._vm_pool:
                        st = self._vm_pool.pop()
                        break

                    if self._vm_total_created < self._vm_limit:
                        self._vm_total_created += 1
                        created_slot = True
                        st = _VMState()
                        break

                    self._vm_cv.wait()

            try:
                # Create / recreate VM only when the seed changes.
                if st.vm is None or st.seed_hash != seed_hash:
                    if st.vm is not None:
                        try:
                            self.rx.destroy_vm(st.vm)
                        except Exception:
                            pass
                        st.vm = None

                    new_vm = self.rx.create_vm()
                    if new_vm is None:
                        raise RuntimeError("RandomX create_vm() returned None")

                    st.vm = new_vm
                    st.seed_hash = seed_hash

                if st.blob_buf is None or len(st.blob_buf) != len(blob):
                    st.blob_buf = (c_ubyte * len(blob))()

                if st.out_buf is None:
                    st.out_buf = (c_ubyte * 32)()

                memmove(st.blob_buf, blob, len(blob))
                st.nonce_ptr = cast(byref(st.blob_buf, nonce_offset), POINTER(c_uint32))

                if st.nonce_ptr is None:
                    raise RuntimeError("failed to create nonce pointer")

                # Probe pointer before native hashing touches it.
                _ = st.nonce_ptr[0]

                tls._checked_out_vm_state = st

            except Exception:
                # Do not leak a partially prepared slot.
                if st is not None and getattr(st, "vm", None) is not None:
                    try:
                        self.rx.destroy_vm(st.vm)
                    except Exception:
                        pass
                    st.vm = None
                    st.seed_hash = b""
                    st.blob_buf = None
                    st.nonce_ptr = None
                    st.out_buf = None

                if created_slot:
                    with self._vm_cv:
                        if self._vm_total_created > 0:
                            self._vm_total_created -= 1
                        self._vm_cv.notify_all()
                raise

        # Mirror into TLS so existing _hash_range() can continue using self._tls
        tls.seed_hash = st.seed_hash
        tls.vm = st.vm
        tls.blob_buf = st.blob_buf
        tls.nonce_ptr = st.nonce_ptr
        tls.out_buf = st.out_buf

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
        tls = getattr(self, "_tls", None)

        try:
            self._ensure_thread_vm(job)
            st = self._tls
            rx_hash_into = self.rx.hash_into
            target64 = int(job.target64) & 0xFFFFFFFFFFFFFFFF

            local_done = 0
            local_found: list[dict] = []

            for i in range(max(0, int(count))):
                if self._stop.is_set():
                    break

                nonce_u32 = (int(start_nonce) + i) & 0xFFFFFFFF
                st.nonce_ptr[0] = nonce_u32
                rx_hash_into(st.vm, st.blob_buf, st.out_buf)
                local_done += 1

                h32 = bytes(st.out_buf)
                tail = int.from_bytes(h32[24:32], "little", signed=False)
                if tail < target64:
                    local_found.append(
                        {
                            "nonce_u32": nonce_u32,
                            "hash_hex": h32.hex(),
                        }
                    )
                    if len(local_found) >= max_results:
                        break

            with out_lock:
                out_hashes.append(local_done)
                if local_found:
                    out_found.extend(local_found[:max_results])

        except Exception as e:
            with out_lock:
                out_errors.append(str(e))

        finally:
            tls = getattr(self, "_tls", None)
            if tls is None:
                return

            st = getattr(tls, "_checked_out_vm_state", None)
            if st is not None:
                # After stop/close, destroy instead of repooling so RAM goes down.
                if self._stop.is_set():
                    if st.vm is not None:
                        try:
                            self.rx.destroy_vm(st.vm)
                        except Exception:
                            pass
                    st.vm = None
                    st.seed_hash = b""
                    st.blob_buf = None
                    st.nonce_ptr = None
                    st.out_buf = None

                    with self._vm_cv:
                        if self._vm_total_created > 0:
                            self._vm_total_created -= 1
                        self._vm_cv.notify_all()
                else:
                    with self._vm_cv:
                        self._vm_pool.append(st)
                        self._vm_cv.notify()

            # Clear thread-local mirror refs so callback-thread churn does not keep
            # stale Python-side buffer references alive forever.
            tls._checked_out_vm_state = None
            tls.seed_hash = b""
            tls.vm = None
            tls.blob_buf = None
            tls.nonce_ptr = None
            tls.out_buf = None

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

        t0 = time.perf_counter()
        self.ensure_seed(job.seed_hash)
        self.reset_stop()


        count = max(1, int(count))
        threads = max(1, int(self.threads))
        per_thread = max(1, count // threads)
        remainder = count % threads

        found: list[dict] = []
        hashes_done_parts: list[int] = []
        errors: list[str] = []
        results_lock = threading.Lock()

        nonce_cursor = int(start_nonce) & 0xFFFFFFFF

        subranges: list[tuple[int, int]] = []
        for i in range(threads):
            take = per_thread + (1 if i < remainder else 0)
            if take <= 0:
                continue
            sub_start = nonce_cursor
            nonce_cursor = (nonce_cursor + take) & 0xFFFFFFFF
            subranges.append((sub_start, take))

        callbacks = []
        for sub_start, take in subranges:
            def make_job(s=sub_start, c=take)-> Callable[[], None]:
                return lambda: self._hash_range(
                    job=job,
                    start_nonce=s,
                    count=c,
                    max_results=max_results,
                    out_found=found,
                    out_hashes=hashes_done_parts,
                    out_errors=errors,
                    out_lock=results_lock,
                )
            cb_func = self.python_runtime.wrap_parallel_void_factory(
                make_job,
                timeout_ms=0xFFFFFFFF,
                gate_task=PYR_TASK_ECHO,
                gate_payload=f"__parallel_make_job__:{job.job_id}:{sub_start}:{take}".encode("utf-8"),
                name=f"make_job_{sub_start}_{take}",
            )
            wrapped_func = self.python_usage.wrap_function(cb_func)
            callbacks.append(wrapped_func)

        self.bridge.invoke_all_void(callbacks)

        hashes_done = int(sum(hashes_done_parts))
        elapsed = time.perf_counter() - t0

        self._last_hashes_done = hashes_done
        self._last_job_id = job.job_id
        self._last_elapsed = elapsed

        if errors:
            self.logger(f"[ParallelMoneroWorker] hashing errors: {' | '.join(errors[:4])}")

        return {
            "job_id": job.job_id,
            "hashes_done": hashes_done,
            "found": found[:max_results],
            "elapsed_sec": elapsed,
        }

    def get_last_hashes_done(self) -> int:
        return int(self._last_hashes_done)

    def get_last_elapsed(self) -> float:
        return float(self._last_elapsed)

    def get_last_job_id(self) -> str:
        return str(self._last_job_id)