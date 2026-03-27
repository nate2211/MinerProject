from __future__ import annotations

import ctypes
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

class PythonJITError(RuntimeError):
    pass


@dataclass
class JITThunk:
    handle: int
    address: int
    kind: str
    _callback_ref: Any


class PythonJIT:
    INT_TARGET = ctypes.CFUNCTYPE(ctypes.c_int, c_void_p)
    VOID_TARGET = ctypes.CFUNCTYPE(None, c_void_p)

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
        return ctypes.CDLL(path)

    def _configure(self) -> None:
        self._dll.PJIT_GetVersion.argtypes = []
        self._dll.PJIT_GetVersion.restype = c_int

        self._dll.PJIT_GetLastErrorA.argtypes = []
        self._dll.PJIT_GetLastErrorA.restype = c_char_p

        self._dll.PJIT_ClearLastError.argtypes = []
        self._dll.PJIT_ClearLastError.restype = None

        self._dll.PJIT_CreateIntThunk0.argtypes = [self.INT_TARGET, c_void_p]
        self._dll.PJIT_CreateIntThunk0.restype = c_void_p

        self._dll.PJIT_CreateVoidThunk0.argtypes = [self.VOID_TARGET, c_void_p]
        self._dll.PJIT_CreateVoidThunk0.restype = c_void_p

        self._dll.PJIT_GetThunkAddress.argtypes = [c_void_p]
        self._dll.PJIT_GetThunkAddress.restype = c_void_p

        self._dll.PJIT_InvokeIntThunk0.argtypes = [c_void_p]
        self._dll.PJIT_InvokeIntThunk0.restype = c_int

        self._dll.PJIT_InvokeVoidThunk0.argtypes = [c_void_p]
        self._dll.PJIT_InvokeVoidThunk0.restype = None

        self._dll.PJIT_DestroyThunk.argtypes = [c_void_p]
        self._dll.PJIT_DestroyThunk.restype = c_int

        self._dll.PJIT_DestroyAllThunks.argtypes = []
        self._dll.PJIT_DestroyAllThunks.restype = None

    def version(self) -> int:
        return int(self._dll.PJIT_GetVersion())

    def last_error(self) -> str:
        msg = self._dll.PJIT_GetLastErrorA()
        if not msg:
            return ""
        return msg.decode("utf-8", errors="replace")

    def _require_handle(self, handle) -> int:
        value = int(c_void_p(handle).value or 0)
        if not value:
            raise PythonJITError(self.last_error() or "JIT call failed")
        return value

    def create_int_thunk0(self, func: Callable[[Any], int], user_data: Optional[int] = None) -> JITThunk:
        cb = self.INT_TARGET(func)
        handle = self._require_handle(self._dll.PJIT_CreateIntThunk0(cb, c_void_p(user_data or 0)))
        addr = self._require_handle(self._dll.PJIT_GetThunkAddress(c_void_p(handle)))
        thunk = JITThunk(handle=handle, address=addr, kind="int0", _callback_ref=cb)
        self._thunks.append(thunk)
        return thunk

    def create_void_thunk0(self, func: Callable[[Any], None], user_data: Optional[int] = None) -> JITThunk:
        cb = self.VOID_TARGET(func)
        handle = self._require_handle(self._dll.PJIT_CreateVoidThunk0(cb, c_void_p(user_data or 0)))
        addr = self._require_handle(self._dll.PJIT_GetThunkAddress(c_void_p(handle)))
        thunk = JITThunk(handle=handle, address=addr, kind="void0", _callback_ref=cb)
        self._thunks.append(thunk)
        return thunk

    def invoke_int0(self, thunk: JITThunk) -> int:
        return int(self._dll.PJIT_InvokeIntThunk0(c_void_p(thunk.handle)))

    def invoke_void0(self, thunk: JITThunk) -> None:
        self._dll.PJIT_InvokeVoidThunk0(c_void_p(thunk.handle))

    def destroy(self, thunk: JITThunk) -> None:
        rc = int(self._dll.PJIT_DestroyThunk(c_void_p(thunk.handle)))
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


@dataclass
class _ThreadState:
    worker_index: int
    vm: Any = None
    blob_buf: Any = None
    nonce_ptr: Any = None
    out_buf: Any = None
    last_seed: bytes = b""
    last_blob: bytes = b""

    assigned_job: Optional[MoneroJob] = None
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


class JITWorker:
    """
    Safe JITWorker:
    - keeps the same API used by miner_core.py
    - does NOT call PJIT_CreateIntThunk0 during bootstrap, because that is what
      is currently crashing in PythonJIT.dll
    - still uses the local RandomX DLL for hashing
    """

    def __init__(
        self,
        *,
        threads: int,
        logger: Optional[Callable[[str], None]],
        randomx: RandomX,
        jit: PythonJIT,
        batch_size: int = 1024,
        python_usage: PythonUsage
    ) -> None:
        self.threads = max(1, int(threads))
        self.logger = logger or (lambda s: None)
        self.rx = randomx
        self.jit = jit
        self.batch_size = max(1, int(batch_size))

        self._stop = threading.Event()
        self._states: list[_ThreadState] = []
        self._threads: list[threading.Thread] = []
        self._mu = threading.RLock()
        self.python_usage = python_usage
        self._bootstrap_workers()

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
            st.thunk = None  # disabled until the DLL callback ABI is confirmed
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
            f"(safe mode: no PJIT_CreateIntThunk0)"
        )

    def _make_callback(self, st: _ThreadState):
        def _cb(_user_data=None) -> int:
            try:
                st.error = None
                st.done_hashes = 0
                st.found = []

                job = st.assigned_job
                if job is None:
                    return 0

                self._ensure_thread_vm(st, job)

                rx_hash_into = self.rx.hash_into
                target64 = int(job.target64) & 0xFFFFFFFFFFFFFFFF

                max_results = max(1, int(st.assigned_max_results))
                start_nonce = int(st.assigned_start_nonce) & 0xFFFFFFFF
                count = max(0, int(st.assigned_count))

                for i in range(count):
                    if self._stop.is_set():
                        break

                    nonce_u32 = (start_nonce + i) & 0xFFFFFFFF
                    st.nonce_ptr[0] = nonce_u32
                    rx_hash_into(st.vm, st.blob_buf, st.out_buf)
                    st.done_hashes += 1

                    h32 = bytes(st.out_buf)
                    tail = int.from_bytes(h32[24:32], "little", signed=False)
                    if tail < target64:
                        st.found.append(
                            {
                                "nonce_u32": nonce_u32,
                                "hash_hex": h32.hex(),
                            }
                        )
                        if len(st.found) >= max_results:
                            break

                return st.done_hashes

            except Exception as e:
                st.error = f"{type(e).__name__}: {e}"
                return -1

        return _cb

    def _ensure_thread_vm(self, st: _ThreadState, job: MoneroJob) -> None:
        seed_changed = (st.last_seed != job.seed_hash)
        blob_changed = (st.last_blob != job.blob)

        if seed_changed:
            self.rx.ensure_seed(job.seed_hash)

            if st.vm is not None:
                try:
                    self.rx.destroy_vm(st.vm)
                except Exception:
                    pass
                st.vm = None

            st.vm = self.rx.create_vm()
            st.last_seed = bytes(job.seed_hash)

        if st.blob_buf is None or len(st.blob_buf) != len(job.blob):
            st.blob_buf = (c_ubyte * len(job.blob))()
            blob_changed = True

        if blob_changed:
            memmove(st.blob_buf, job.blob, len(job.blob))
            st.last_blob = bytes(job.blob)

        st.nonce_ptr = cast(byref(st.blob_buf, int(job.nonce_offset)), POINTER(c_uint32))

    def _thread_main(self, st: _ThreadState) -> None:
        while not self._stop.is_set():
            st.start_event.wait(0.1)
            if self._stop.is_set():
                break
            if not st.start_event.is_set():
                continue

            st.start_event.clear()
            st.done_event.clear()
            st.busy = True
            try:
                st.callback(None)
            except Exception as e:
                st.error = f"{type(e).__name__}: {e}"
            finally:
                st.busy = False
                st.done_event.set()

    def hash_job(
        self,
        *,
        job: MoneroJob,
        start_nonce: int,
        count: int,
        max_results: int,
    ) -> dict:
        count = max(0, int(count))
        if count <= 0:
            return {
                "job_id": job.job_id,
                "hashes_done": 0,
                "found": [],
                "elapsed_sec": 0.0,
                "errors": [],
            }

        t0 = time.perf_counter()

        threads = min(self.threads, count)
        per_thread = count // threads
        remainder = count % threads

        cursor = int(start_nonce) & 0xFFFFFFFF
        active_states: list[_ThreadState] = []

        for i in range(threads):
            take = per_thread + (1 if i < remainder else 0)
            if take <= 0:
                continue

            st = self._states[i]
            st.assigned_job = job
            st.assigned_start_nonce = cursor
            st.assigned_count = take
            st.assigned_max_results = max_results
            st.done_hashes = 0
            st.found = []
            st.error = None
            st.done_event.clear()

            cursor = (cursor + take) & 0xFFFFFFFF
            active_states.append(st)

        for st in active_states:
            st.start_event.set()

        for st in active_states:
            st.done_event.wait()

        hashes_done = 0
        found: list[dict] = []
        errors: list[str] = []

        for st in active_states:
            hashes_done += int(st.done_hashes or 0)
            if st.found:
                found.extend(st.found)
            if st.error:
                errors.append(f"worker[{st.worker_index}] {st.error}")

        found.sort(key=lambda x: int(x.get("nonce_u32", 0)))
        if len(found) > max_results:
            found = found[:max_results]

        return {
            "job_id": job.job_id,
            "hashes_done": hashes_done,
            "found": found,
            "elapsed_sec": max(0.0, time.perf_counter() - t0),
            "errors": errors,
        }

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

        for st in self._states:
            if st.vm is not None:
                try:
                    self.rx.destroy_vm(st.vm)
                except Exception:
                    pass
                st.vm = None