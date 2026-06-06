# monero_hot_hash.py
from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence


# =============================================================================
# Native status codes from MoneroHashLoop.dll / HotHash-style DLL
# =============================================================================

HH_OK = 0
HH_STOPPED = 1
HH_STALE = 2

HH_BAD_ARGUMENT = -1
HH_CANDIDATE_OVERFLOW = -2
HH_HASH_FUNCTION_FAILED = -3
HH_INTERNAL_ERROR = -4


_STATUS_NAMES = {
    HH_OK: "HH_OK",
    HH_STOPPED: "HH_STOPPED",
    HH_STALE: "HH_STALE",
    HH_BAD_ARGUMENT: "HH_BAD_ARGUMENT",
    HH_CANDIDATE_OVERFLOW: "HH_CANDIDATE_OVERFLOW",
    HH_HASH_FUNCTION_FAILED: "HH_HASH_FUNCTION_FAILED",
    HH_INTERNAL_ERROR: "HH_INTERNAL_ERROR",
}


# =============================================================================
# ctypes structures matching the C++ ABI
# =============================================================================

class HH_Candidate(ctypes.Structure):
    _fields_ = [
        ("nonce_u32", ctypes.c_uint32),
        ("reserved0", ctypes.c_uint32),
        ("tail64", ctypes.c_uint64),
        ("hash", ctypes.c_uint8 * 32),
    ]


class HH_Result(ctypes.Structure):
    _fields_ = [
        ("done_hashes", ctypes.c_uint64),
        ("hit_count", ctypes.c_uint64),
        ("best_tail64", ctypes.c_uint64),
        ("best_nonce_u32", ctypes.c_uint32),
        ("candidate_count", ctypes.c_uint32),
        ("overflow_count", ctypes.c_uint32),
        ("status", ctypes.c_int32),
        ("reserved0", ctypes.c_uint32),
    ]


# Fake/smoke-test callback signature.
# For real mining, do NOT pass a Python callback.
# Pass the native address of randomx_calculate_hash.
RandomXHashCallback = ctypes.CFUNCTYPE(
    None,
    ctypes.c_void_p,   # vm
    ctypes.c_void_p,   # input
    ctypes.c_size_t,   # input_size
    ctypes.c_void_p,   # output32
)


@dataclass
class MoneroHotHashResult:
    status: int
    status_name: str
    done_hashes: int
    hit_count: int
    best_tail64: int
    best_nonce_u32: int
    candidate_count: int
    overflow_count: int
    candidates: list[dict]
    blob: bytearray

    @property
    def ok(self) -> bool:
        return self.status in (HH_OK, HH_STOPPED, HH_STALE, HH_CANDIDATE_OVERFLOW)

    @property
    def stopped(self) -> bool:
        return self.status == HH_STOPPED

    @property
    def stale(self) -> bool:
        return self.status == HH_STALE

    @property
    def overflowed(self) -> bool:
        return self.overflow_count > 0 or self.status == HH_CANDIDATE_OVERFLOW


class MoneroHotHashError(RuntimeError):
    pass


class MoneroHotHashControl:
    """
    Shared native-control state.

    Pass one of these to run_hot_loop(..., control=control) if you want
    another Python thread to stop or stale the native loop while it is running.

    Example:
        control = MoneroHotHashControl(generation=10)

        # In another thread:
        control.stop()

        # Or when a new job arrives:
        control.advance_generation()
    """

    def __init__(self, generation: int = 0) -> None:
        self.stop_flag = ctypes.c_int(0)
        self.current_generation = ctypes.c_uint64(int(generation) & 0xFFFFFFFFFFFFFFFF)

    @property
    def generation(self) -> int:
        return int(self.current_generation.value) & 0xFFFFFFFFFFFFFFFF

    def reset_stop(self) -> None:
        self.stop_flag.value = 0

    def stop(self) -> None:
        self.stop_flag.value = 1

    def set_generation(self, generation: int) -> None:
        self.current_generation.value = int(generation) & 0xFFFFFFFFFFFFFFFF

    def advance_generation(self) -> int:
        self.current_generation.value = (int(self.current_generation.value) + 1) & 0xFFFFFFFFFFFFFFFF
        return int(self.current_generation.value)


class MoneroHashLoopDLL:
    """
    ctypes API for MoneroHashLoop.dll.

    Expected native exports from your C++ DLL:

        HH_GetVersion()
        HH_GetLastErrorA()
        HH_ClearLastError()
        HH_SizeOfCandidate()
        HH_SizeOfResult()
        HH_RunHotLoop(...)

    The wrapper also tries MHL_* names as a fallback, so you can rename exports
    later if you want.
    """

    DLL_NAME = "MoneroHashLoop.dll"

    def __init__(self, dll_path: Optional[str | os.PathLike[str]] = None) -> None:
        self.dll_path = self._resolve_dll_path(dll_path or self.DLL_NAME)
        self._dll_dir_handle = None
        self._dll = self._load_dll(self.dll_path)
        self._prefix = self._detect_prefix()
        self._configure_exports()
        self._validate_abi()

    # -------------------------------------------------------------------------
    # Path / loading
    # -------------------------------------------------------------------------

    @classmethod
    def load_same_dir(cls) -> "MoneroHashLoopDLL":
        return cls(cls.DLL_NAME)

    @staticmethod
    def _module_dir() -> Path:
        return Path(__file__).resolve().parent

    def _resolve_dll_path(self, raw: str | os.PathLike[str]) -> str:
        p = Path(raw)

        candidates: list[Path] = []

        # If caller passed absolute path, try it first.
        candidates.append(p)

        # Same directory as this Python API file.
        candidates.append(self._module_dir() / p.name)

        # PyInstaller temp extraction directory.
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / p.name)

        # Current working directory.
        candidates.append(Path.cwd() / p.name)

        # Same directory as python.exe / bundled exe.
        try:
            candidates.append(Path(sys.executable).resolve().parent / p.name)
        except Exception:
            pass

        for cand in candidates:
            try:
                if cand.exists():
                    return str(cand.resolve())
            except Exception:
                continue

        # Return same-dir path as the most useful error path.
        return str((self._module_dir() / p.name).resolve())

    def _load_dll(self, path: str):
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"{self.DLL_NAME} not found: {path}\n"
                f"Put {self.DLL_NAME} in the same folder as monero_hot_hash.py."
            )

        dll_dir = os.path.dirname(path)

        if os.name == "nt" and dll_dir:
            try:
                self._dll_dir_handle = os.add_dll_directory(dll_dir)
            except Exception:
                self._dll_dir_handle = None

        # C++ exports are __cdecl, so CDLL is correct.
        return ctypes.CDLL(path)

    # -------------------------------------------------------------------------
    # Export binding
    # -------------------------------------------------------------------------

    def _has_export(self, name: str) -> bool:
        try:
            getattr(self._dll, name)
            return True
        except AttributeError:
            return False

    def _detect_prefix(self) -> str:
        # Current C++ code exports HH_*.
        if self._has_export("HH_RunHotLoop"):
            return "HH"

        # Optional future prefix if you rename exports.
        if self._has_export("MHL_RunHotLoop"):
            return "MHL"

        raise MoneroHotHashError(
            "Could not find HH_RunHotLoop or MHL_RunHotLoop in MoneroHashLoop.dll. "
            "Make sure the DLL exports the hot-loop API with extern \"C\" __declspec(dllexport)."
        )

    def _fn(self, suffix: str):
        return getattr(self._dll, f"{self._prefix}_{suffix}")

    def _configure_exports(self) -> None:
        get_version = self._fn("GetVersion")
        get_version.argtypes = []
        get_version.restype = ctypes.c_int
        self._get_version = get_version

        get_last_error = self._fn("GetLastErrorA")
        get_last_error.argtypes = []
        get_last_error.restype = ctypes.c_char_p
        self._get_last_error = get_last_error

        clear_last_error = self._fn("ClearLastError")
        clear_last_error.argtypes = []
        clear_last_error.restype = None
        self._clear_last_error = clear_last_error

        size_candidate = self._fn("SizeOfCandidate")
        size_candidate.argtypes = []
        size_candidate.restype = ctypes.c_uint32
        self._size_candidate = size_candidate

        size_result = self._fn("SizeOfResult")
        size_result.argtypes = []
        size_result.restype = ctypes.c_uint32
        self._size_result = size_result

        run_hot_loop = self._fn("RunHotLoop")
        run_hot_loop.argtypes = [
            ctypes.c_void_p,                         # hash_fn
            ctypes.c_void_p,                         # vm
            ctypes.POINTER(ctypes.c_uint8),           # blob
            ctypes.c_size_t,                          # blob_size
            ctypes.c_uint32,                          # nonce_offset
            ctypes.c_uint32,                          # start_nonce
            ctypes.c_uint32,                          # stride
            ctypes.c_uint64,                          # count
            ctypes.c_uint64,                          # target64
            ctypes.POINTER(ctypes.c_int),             # stop_flag
            ctypes.c_uint32,                          # stale_mask
            ctypes.POINTER(ctypes.c_uint64),          # current_generation
            ctypes.c_uint64,                          # generation
            ctypes.POINTER(HH_Candidate),             # candidates
            ctypes.c_uint32,                          # max_candidates
            ctypes.POINTER(HH_Result),                # result
        ]
        run_hot_loop.restype = ctypes.c_int
        self._run_hot_loop = run_hot_loop

    def _validate_abi(self) -> None:
        native_candidate_size = int(self._size_candidate())
        python_candidate_size = ctypes.sizeof(HH_Candidate)

        if native_candidate_size != python_candidate_size:
            raise MoneroHotHashError(
                f"HH_Candidate ABI size mismatch: "
                f"native={native_candidate_size}, python={python_candidate_size}"
            )

        native_result_size = int(self._size_result())
        python_result_size = ctypes.sizeof(HH_Result)

        if native_result_size != python_result_size:
            raise MoneroHotHashError(
                f"HH_Result ABI size mismatch: "
                f"native={native_result_size}, python={python_result_size}"
            )

    # -------------------------------------------------------------------------
    # Basic API
    # -------------------------------------------------------------------------

    @property
    def dll(self):
        return self._dll

    @property
    def prefix(self) -> str:
        return self._prefix

    def version(self) -> int:
        return int(self._get_version())

    def clear_last_error(self) -> None:
        self._clear_last_error()

    def last_error(self) -> str:
        raw = self._get_last_error()
        if not raw:
            return ""
        return raw.decode("utf-8", errors="replace")

    def close(self) -> None:
        if self._dll_dir_handle is not None:
            try:
                self._dll_dir_handle.close()
            except Exception:
                pass
            self._dll_dir_handle = None

    def __enter__(self) -> "MoneroHashLoopDLL":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # -------------------------------------------------------------------------
    # Pointer helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def address_of_function(fn: Any) -> int:
        """
        Get raw address of a ctypes function.

        Example:
            rx_hash_ptr = MoneroHashLoopDLL.address_of_function(
                randomx_lib.randomx_calculate_hash
            )
        """
        value = ctypes.cast(fn, ctypes.c_void_p).value
        return int(value or 0)

    @staticmethod
    def address_of_pointer(ptr: Any) -> int:
        """
        Get raw address from a ctypes pointer/c_void_p/etc.
        """
        if ptr is None:
            return 0

        if isinstance(ptr, int):
            return int(ptr)

        if isinstance(ptr, ctypes.c_void_p):
            return int(ptr.value or 0)

        value = ctypes.cast(ptr, ctypes.c_void_p).value
        return int(value or 0)

    @staticmethod
    def randomx_hash_function_address(randomx: Any) -> int:
        """
        Best-effort helper for common RandomX wrappers.

        Works if your wrapper exposes one of:
            randomx.randomx_calculate_hash
            randomx.lib.randomx_calculate_hash
            randomx._dll.randomx_calculate_hash
            randomx.dll.randomx_calculate_hash
            randomx._lib.randomx_calculate_hash
        """
        candidates = [
            randomx,
            getattr(randomx, "lib", None),
            getattr(randomx, "_lib", None),
            getattr(randomx, "dll", None),
            getattr(randomx, "_dll", None),
            getattr(randomx, "randomx_dll", None),
        ]

        for obj in candidates:
            if obj is None:
                continue

            fn = getattr(obj, "randomx_calculate_hash", None)
            if fn is not None:
                return MoneroHashLoopDLL.address_of_function(fn)

        raise MoneroHotHashError(
            "Could not find randomx_calculate_hash on the provided RandomX wrapper. "
            "Pass hash_fn_ptr manually."
        )

    @staticmethod
    def randomx_vm_address(vm: Any) -> int:
        """
        Convert common VM pointer shapes into a raw integer address.
        """
        if vm is None:
            return 0

        if isinstance(vm, int):
            return int(vm)

        if isinstance(vm, ctypes.c_void_p):
            return int(vm.value or 0)

        return MoneroHashLoopDLL.address_of_pointer(vm)

    # -------------------------------------------------------------------------
    # Main hot-loop API
    # -------------------------------------------------------------------------

    def run_hot_loop(
        self,
        *,
        hash_fn_ptr: int,
        vm_ptr: int,
        blob: bytearray | bytes | memoryview,
        nonce_offset: int,
        start_nonce: int,
        stride: int,
        count: int,
        target64: int,
        control: Optional[MoneroHotHashControl] = None,
        stop_flag: Optional[ctypes.c_int] = None,
        current_generation: Optional[ctypes.c_uint64] = None,
        generation: int = 0,
        stale_mask: int = 0x3FFF,
        max_candidates: int = 64,
        raise_on_error: bool = True,
        allow_blob_copy: bool = True,
    ) -> MoneroHotHashResult:
        """
        Run native Monero/RandomX hot hash loop.

        Required:
            hash_fn_ptr:
                Native address of randomx_calculate_hash.
                Do NOT pass a Python callback for real mining.

            vm_ptr:
                Native randomx_vm* address.

            blob:
                Mutable block hashing blob. bytearray is best.
                If bytes/memoryview is passed and allow_blob_copy=True,
                this wrapper copies into bytearray.

            nonce_offset:
                Offset where uint32 nonce is written little-endian.

            start_nonce:
                First nonce.

            stride:
                Nonce stride.

            count:
                Number of hashes to run.

            target64:
                Candidate if tail64 < target64.

        Returns:
            MoneroHotHashResult with candidate dictionaries.
        """
        if not hash_fn_ptr:
            raise MoneroHotHashError("hash_fn_ptr is null")

        if not vm_ptr:
            raise MoneroHotHashError("vm_ptr is null")

        work_blob = self._coerce_blob(blob, allow_blob_copy=allow_blob_copy)

        if nonce_offset < 0 or nonce_offset + 4 > len(work_blob):
            raise ValueError(
                f"nonce_offset is outside blob: nonce_offset={nonce_offset}, blob_len={len(work_blob)}"
            )

        safe_stride = max(1, int(stride))
        safe_count = max(0, int(count))
        safe_target64 = int(target64) & 0xFFFFFFFFFFFFFFFF
        safe_generation = int(generation) & 0xFFFFFFFFFFFFFFFF
        safe_stale_mask = int(stale_mask) & 0xFFFFFFFF

        safe_max_candidates = max(0, int(max_candidates))

        if control is not None:
            stop_ref = control.stop_flag
            generation_ref = control.current_generation
            if generation == 0:
                safe_generation = int(control.current_generation.value) & 0xFFFFFFFFFFFFFFFF
        else:
            stop_ref = stop_flag if stop_flag is not None else ctypes.c_int(0)
            generation_ref = (
                current_generation
                if current_generation is not None
                else ctypes.c_uint64(safe_generation)
            )

        blob_arr = (ctypes.c_uint8 * len(work_blob)).from_buffer(work_blob)

        if safe_max_candidates > 0:
            candidates_arr = (HH_Candidate * safe_max_candidates)()
            candidates_ptr = candidates_arr
        else:
            candidates_arr = None
            candidates_ptr = None

        native_result = HH_Result()

        self.clear_last_error()

        rc = int(
            self._run_hot_loop(
                ctypes.c_void_p(int(hash_fn_ptr)),
                ctypes.c_void_p(int(vm_ptr)),
                blob_arr,
                ctypes.c_size_t(len(work_blob)),
                ctypes.c_uint32(int(nonce_offset) & 0xFFFFFFFF),
                ctypes.c_uint32(int(start_nonce) & 0xFFFFFFFF),
                ctypes.c_uint32(safe_stride & 0xFFFFFFFF),
                ctypes.c_uint64(safe_count & 0xFFFFFFFFFFFFFFFF),
                ctypes.c_uint64(safe_target64),
                ctypes.byref(stop_ref),
                ctypes.c_uint32(safe_stale_mask),
                ctypes.byref(generation_ref),
                ctypes.c_uint64(safe_generation),
                candidates_ptr,
                ctypes.c_uint32(safe_max_candidates & 0xFFFFFFFF),
                ctypes.byref(native_result),
            )
        )

        candidates = self._extract_candidates(candidates_arr, native_result, safe_max_candidates)

        result = MoneroHotHashResult(
            status=rc,
            status_name=_STATUS_NAMES.get(rc, f"UNKNOWN_STATUS_{rc}"),
            done_hashes=int(native_result.done_hashes),
            hit_count=int(native_result.hit_count),
            best_tail64=int(native_result.best_tail64) & 0xFFFFFFFFFFFFFFFF,
            best_nonce_u32=int(native_result.best_nonce_u32) & 0xFFFFFFFF,
            candidate_count=int(native_result.candidate_count),
            overflow_count=int(native_result.overflow_count),
            candidates=candidates,
            blob=work_blob,
        )

        if raise_on_error and rc < 0 and rc != HH_CANDIDATE_OVERFLOW:
            err = self.last_error()
            raise MoneroHotHashError(err or f"MoneroHashLoop failed with {result.status_name}")

        return result

    def run_randomx_job(
        self,
        *,
        randomx: Any,
        vm: Any,
        blob: bytearray | bytes | memoryview,
        nonce_offset: int,
        start_nonce: int,
        stride: int,
        count: int,
        target64: int,
        control: Optional[MoneroHotHashControl] = None,
        generation: int = 0,
        stale_mask: int = 0x3FFF,
        max_candidates: int = 64,
        raise_on_error: bool = True,
    ) -> MoneroHotHashResult:
        """
        Convenience helper when you have a RandomX wrapper object.

        Example:
            hot = MoneroHashLoopDLL()
            result = hot.run_randomx_job(
                randomx=rx,
                vm=rx_vm,
                blob=job_blob,
                nonce_offset=39,
                start_nonce=0,
                stride=1,
                count=10000,
                target64=target64,
            )
        """
        hash_fn_ptr = self.randomx_hash_function_address(randomx)
        vm_ptr = self.randomx_vm_address(vm)

        return self.run_hot_loop(
            hash_fn_ptr=hash_fn_ptr,
            vm_ptr=vm_ptr,
            blob=blob,
            nonce_offset=nonce_offset,
            start_nonce=start_nonce,
            stride=stride,
            count=count,
            target64=target64,
            control=control,
            generation=generation,
            stale_mask=stale_mask,
            max_candidates=max_candidates,
            raise_on_error=raise_on_error,
        )

    # -------------------------------------------------------------------------
    # Conversion helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _coerce_blob(
        blob: bytearray | bytes | memoryview,
        *,
        allow_blob_copy: bool,
    ) -> bytearray:
        if isinstance(blob, bytearray):
            return blob

        if isinstance(blob, bytes):
            if not allow_blob_copy:
                raise TypeError("blob is bytes; pass bytearray or set allow_blob_copy=True")
            return bytearray(blob)

        if isinstance(blob, memoryview):
            if blob.readonly:
                if not allow_blob_copy:
                    raise TypeError("blob memoryview is read-only; pass mutable buffer")
                return bytearray(blob.tobytes())

            try:
                return bytearray(blob)
            except Exception:
                if not allow_blob_copy:
                    raise
                return bytearray(blob.tobytes())

        raise TypeError(f"unsupported blob type: {type(blob).__name__}")

    @staticmethod
    def _share_diff_est(tail64: int) -> float:
        tail64 = int(tail64) & 0xFFFFFFFFFFFFFFFF
        if tail64 <= 0:
            return float("inf")
        return float((1 << 64) / tail64)

    @classmethod
    def _extract_candidates(
        cls,
        candidates_arr: Optional[Sequence[HH_Candidate]],
        native_result: HH_Result,
        max_candidates: int,
    ) -> list[dict]:
        if candidates_arr is None or max_candidates <= 0:
            return []

        n = min(int(native_result.candidate_count), int(max_candidates))
        out: list[dict] = []

        for i in range(n):
            c = candidates_arr[i]
            nonce_u32 = int(c.nonce_u32) & 0xFFFFFFFF
            tail64 = int(c.tail64) & 0xFFFFFFFFFFFFFFFF
            hash_hex = bytes(c.hash).hex()

            out.append(
                {
                    "nonce_u32": nonce_u32,
                    "hash_hex": hash_hex,
                    "tail64": tail64,
                    "share_diff_est": cls._share_diff_est(tail64),
                }
            )

        return out


# =============================================================================
# Optional fake-hash smoke test
# =============================================================================

@RandomXHashCallback
def _fake_hash_callback(vm, input_ptr, input_size, output_ptr):
    """
    Fake hash for testing MoneroHashLoop.dll without RandomX.

    This is ONLY for smoke testing. Do not use Python callbacks for real mining.
    """
    data = ctypes.string_at(input_ptr, input_size)
    out = (ctypes.c_uint8 * 32).from_address(int(output_ptr))

    # Test assumes nonce_offset=39.
    nonce = 0
    if len(data) >= 43:
        nonce = int.from_bytes(data[39:43], "little", signed=False)

    # Deterministic fake 32-byte output.
    for i in range(32):
        out[i] = ((nonce >> ((i % 4) * 8)) + i * 19 + 7) & 0xFF

    # Force a few candidate hits by making tail64 tiny.
    if nonce in (7, 13, 21, 42):
        for i in range(24, 32):
            out[i] = 0
        out[24] = nonce & 0xFF


def smoke_test() -> None:
    hot = MoneroHashLoopDLL.load_same_dir()

    blob = bytearray(80)
    nonce_offset = 39

    control = MoneroHotHashControl(generation=123)

    result = hot.run_hot_loop(
        hash_fn_ptr=MoneroHashLoopDLL.address_of_function(_fake_hash_callback),
        vm_ptr=1,  # fake non-null vm; callback ignores it
        blob=blob,
        nonce_offset=nonce_offset,
        start_nonce=0,
        stride=1,
        count=64,
        target64=100,
        control=control,
        generation=123,
        stale_mask=7,
        max_candidates=16,
    )

    print("dll:", hot.dll_path)
    print("prefix:", hot.prefix)
    print("version:", hot.version())
    print("status:", result.status, result.status_name)
    print("done_hashes:", result.done_hashes)
    print("hit_count:", result.hit_count)
    print("best_tail64:", result.best_tail64)
    print("best_nonce_u32:", result.best_nonce_u32)
    print("candidate_count:", result.candidate_count)
    print("overflow_count:", result.overflow_count)
    print("candidates:")
    for c in result.candidates:
        print(" ", c)

    assert result.done_hashes == 64
    assert result.hit_count >= 4
    assert any(c["nonce_u32"] == 7 for c in result.candidates)
    assert any(c["nonce_u32"] == 13 for c in result.candidates)
    assert any(c["nonce_u32"] == 21 for c in result.candidates)

    print("MoneroHashLoop fake smoke test passed.")


if __name__ == "__main__":
    smoke_test()