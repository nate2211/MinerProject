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
    c_size_t,
    c_uint32,
    c_ubyte,
    c_void_p,
)
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from monero_job import MoneroJob
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

    def __init__(self, logger: Optional[Callable[[str], None]] = None, dll_path: str = "") -> None:
        self.logger = logger or (lambda s: None)
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

            self.dll.invoke_all_parallel.argtypes = [c_void_p, c_int]
            self.dll.invoke_all_parallel.restype = None

            self.available = True
            self.logger(f"[ParallelPythonBridge] Loaded DLL: {self.dll_path}")
        except Exception as e:
            self.available = False
            self.dll = None
            self.logger(f"[ParallelPythonBridge] Failed to load DLL: {e}")

    def make_void_callback(self, func: Callable[[], None]):
        return self.PythonCallback(func)

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
            n = min(len(data), max(0, int(size) - 1))
            if n > 0:
                ctypes.memmove(buf, data, n)
            if size > 0:
                ctypes.memset(ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer_copy(b"\x00"))), 0, 0)
        return self.StringCallback(cb), ctypes.create_string_buffer(buffer_size)

    def invoke_all_void(self, callbacks: list) -> None:
        if not self.available or self.dll is None or not callbacks:
            for cb in callbacks:
                cb()
            return

        descs = []
        for cb in callbacks:
            descs.append(
                self.PythonCallDescriptor(
                    c_void_p(cast(cb, c_void_p).value),
                    c_void_p(),
                    0,
                    self.TYPE_VOID,
                )
            )

        arr_t = self.PythonCallDescriptor * len(descs)
        arr = arr_t(*descs)
        self.dll.invoke_all_parallel(cast(arr, c_void_p), len(descs))

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


class ParallelMoneroWorker:
    """
    A worker-oriented Monero hasher that uses ParallelPython callback exports
    to dispatch multiple local hashing jobs in parallel.

    Notes:
      - hashing is still real RandomX hashing via randomx_ctypes
      - ParallelPython is used for callback orchestration
      - miner threads param is respected by creating that many callback jobs
      - one VM per Python worker thread via thread-local state
    """

    def __init__(
        self,
        *,
        threads: int = 1,
        logger: Optional[Callable[[str], None]] = None,
        randomx: Optional[RandomX] = None,
        dll_path: str = "",
        batch_size: int = 1024,
    ) -> None:
        self.logger = logger or (lambda s: None)
        self.threads = max(1, int(threads))
        self.batch_size = max(1, int(batch_size))
        self.rx = randomx or RandomX(self.logger)
        self.bridge = ParallelPythonBridge(logger=self.logger, dll_path=dll_path)

        self._tls = _ThreadState()
        self._seed_lock = threading.RLock()
        self._prepared_seed: bytes = b""
        self._stop = threading.Event()
        self._last_hashes_done = 0
        self._last_job_id = ""
        self._last_elapsed = 0.0

    def stop(self) -> None:
        self._stop.set()

    def reset_stop(self) -> None:
        self._stop.clear()

    def close(self) -> None:
        self._stop.set()

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
        st = self._tls

        if st.seed_hash != job.seed_hash or st.vm is None:
            if st.vm is not None:
                try:
                    self.rx.destroy_vm(st.vm)
                except Exception:
                    pass
                st.vm = None
            st.vm = self.rx.create_vm()
            st.seed_hash = bytes(job.seed_hash)

        if st.blob_buf is None or len(st.blob_buf) != len(job.blob):
            st.blob_buf = (c_ubyte * len(job.blob))()

        memmove(st.blob_buf, job.blob, len(job.blob))
        st.nonce_ptr = cast(byref(st.blob_buf, job.nonce_offset), POINTER(c_uint32))

        if st.out_buf is None:
            st.out_buf = (c_ubyte * 32)()

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
    ) -> None:
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

            out_hashes.append(local_done)
            if local_found:
                out_found.extend(local_found[:max_results])

        except Exception as e:
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
        callbacks = []

        nonce_cursor = int(start_nonce) & 0xFFFFFFFF

        for i in range(threads):
            take = per_thread + (1 if i < remainder else 0)
            if take <= 0:
                continue
            sub_start = nonce_cursor
            nonce_cursor = (nonce_cursor + take) & 0xFFFFFFFF

            def make_job(s=sub_start, c=take):
                return lambda: self._hash_range(
                    job=job,
                    start_nonce=s,
                    count=c,
                    max_results=max_results,
                    out_found=found,
                    out_hashes=hashes_done_parts,
                    out_errors=errors,
                )

            callbacks.append(self.bridge.make_void_callback(make_job()))

        self.bridge.invoke_all_void(callbacks)

        hashes_done = int(sum(hashes_done_parts))
        elapsed = time.perf_counter() - t0

        self._last_hashes_done = hashes_done
        self._last_job_id = job.job_id
        self._last_elapsed = elapsed

        if errors:
            self.logger(f"[ParallelMoneroWorker] callback errors: {' | '.join(errors[:4])}")

        # Example use of the other export types for lightweight diagnostics/state callbacks.
        int_cb = self.bridge.make_int_callback(lambda: hashes_done)
        bool_cb = self.bridge.make_bool_callback(lambda: len(found) > 0)
        double_cb = self.bridge.make_double_callback(lambda: elapsed)
        string_cb = self.bridge.make_string_callback(lambda: job.job_id)[0]

        # invoke them so the bridge actually uses the export family requested
        _ = self.bridge.invoke_int(int_cb)
        _ = self.bridge.invoke_bool(bool_cb)
        _ = self.bridge.invoke_double(double_cb)
        _ = self.bridge.invoke_string(string_cb)

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