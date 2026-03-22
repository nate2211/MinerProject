from __future__ import annotations

import os
import struct
import sys
import threading
from ctypes import (
    CDLL,
    POINTER,
    addressof,
    c_char,
    c_char_p,
    c_int,
    c_uint32,
    c_void_p,
    create_string_buffer,
    string_at,
)
from pathlib import Path
from typing import Dict, List, Optional, Sequence


RANDOMX_DATASET_ITEM_BYTES = 64
DEFAULT_RANDOMX_CACHE_BYTES = 256 * 1024 * 1024

_SNAPSHOT_ALLOW_CACHE = True
_SNAPSHOT_ALLOW_DATASET = True


class VirtualASICError(RuntimeError):
    pass


def _as_void_p_from_buffer(buf) -> c_void_p:
    try:
        return c_void_p(addressof(buf))
    except Exception as e:
        raise VirtualASICError(f"Could not get raw pointer for ctypes buffer: {e}") from e


def _u32(value: int) -> c_uint32:
    return c_uint32(int(value) & 0xFFFFFFFF)


def _logger_or_nop(logger):
    return logger if callable(logger) else (lambda _msg: None)


def _resource_roots() -> List[Path]:
    roots: List[Path] = []

    try:
        roots.append(Path.cwd())
    except Exception:
        pass

    try:
        roots.append(Path(__file__).resolve().parent)
    except Exception:
        pass

    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        try:
            roots.append(Path(meipass))
        except Exception:
            pass

    exe = getattr(sys, "executable", "")
    if exe:
        try:
            roots.append(Path(exe).resolve().parent)
        except Exception:
            pass

    out: List[Path] = []
    seen = set()
    for p in roots:
        try:
            rp = p.resolve()
        except Exception:
            rp = p
        key = str(rp).lower()
        if key not in seen:
            seen.add(key)
            out.append(rp)
    return out


def resolve_resource_path(user_value: str, *, env_var: str = "", fallback_names: Sequence[str] = ()) -> str:
    raw = str(user_value or "").strip()
    candidates: List[Path] = []

    if raw:
        p = Path(raw)
        candidates.append(p)
        if not p.is_absolute():
            for root in _resource_roots():
                candidates.append(root / raw)

    if env_var:
        env_value = os.environ.get(env_var, "").strip()
        if env_value:
            candidates.append(Path(env_value))

    for name in fallback_names:
        if not name:
            continue
        for root in _resource_roots():
            candidates.append(root / name)

    seen = set()
    for cand in candidates:
        try:
            rp = cand.resolve()
        except Exception:
            rp = cand
        key = str(rp).lower()
        if key in seen:
            continue
        seen.add(key)
        if rp.exists():
            return str(rp)

    return raw


class _VirtualASICDll:
    def __init__(self, dll_path: str = "", logger=None) -> None:
        self.logger = _logger_or_nop(logger)
        self.dll_path = resolve_resource_path(
            dll_path,
            env_var="VIRTUALASIC_LIB",
            fallback_names=("VirtualASIC.dll", "virtualasic.dll"),
        )
        if not self.dll_path:
            raise VirtualASICError("Could not resolve VirtualASIC.dll. Set VIRTUALASIC_LIB or provide a DLL path.")

        self._dll_dirs: List[object] = []
        self.lib = self._load_cdll(self.dll_path)
        self._bind()

    def _load_cdll(self, dll_path: str) -> CDLL:
        p = Path(dll_path)
        if not p.exists():
            raise VirtualASICError(f"VirtualASIC DLL not found: {dll_path}")

        try:
            if hasattr(os, "add_dll_directory"):
                for root in {str(p.parent), *(str(r) for r in _resource_roots())}:
                    try:
                        self._dll_dirs.append(os.add_dll_directory(root))
                    except Exception:
                        pass
        except Exception:
            pass

        try:
            lib = CDLL(str(p))
            self.logger(f"[VirtualASIC] Loaded DLL: {p}")
            return lib
        except Exception as e:
            raise VirtualASICError(f"Failed to load VirtualASIC DLL '{p}': {e}") from e

    def _bind(self) -> None:
        L = self.lib
        L.vasic_create.restype = c_void_p
        L.vasic_create.argtypes = []
        L.vasic_create_ex.restype = c_void_p
        L.vasic_create_ex.argtypes = [c_uint32]
        L.vasic_destroy.restype = None
        L.vasic_destroy.argtypes = [c_void_p]
        L.vasic_reset.restype = c_int
        L.vasic_reset.argtypes = [c_void_p]
        L.vasic_set_core_count.restype = c_int
        L.vasic_set_core_count.argtypes = [c_void_p, c_uint32]
        L.vasic_get_core_count.restype = c_uint32
        L.vasic_get_core_count.argtypes = [c_void_p]
        L.vasic_copy_last_error.restype = c_int
        L.vasic_copy_last_error.argtypes = [c_void_p, POINTER(c_char), c_uint32]
        L.vasic_create_buffer.restype = c_uint32
        L.vasic_create_buffer.argtypes = [c_void_p, c_uint32]
        L.vasic_release_buffer.restype = c_int
        L.vasic_release_buffer.argtypes = [c_void_p, c_uint32]
        L.vasic_write_buffer.restype = c_int
        L.vasic_write_buffer.argtypes = [c_void_p, c_uint32, c_uint32, c_void_p, c_uint32]
        L.vasic_read_buffer.restype = c_int
        L.vasic_read_buffer.argtypes = [c_void_p, c_uint32, c_uint32, c_void_p, c_uint32]
        L.vasic_load_kernel_source.restype = c_uint32
        L.vasic_load_kernel_source.argtypes = [c_void_p, c_char_p, c_char_p]
        L.vasic_load_kernel_file.restype = c_uint32
        L.vasic_load_kernel_file.argtypes = [c_void_p, c_char_p, c_char_p]
        L.vasic_release_kernel.restype = c_int
        L.vasic_release_kernel.argtypes = [c_void_p, c_uint32]
        L.vasic_set_kernel_arg_buffer.restype = c_int
        L.vasic_set_kernel_arg_buffer.argtypes = [c_void_p, c_uint32, c_uint32, c_uint32]
        L.vasic_set_kernel_arg_u32.restype = c_int
        L.vasic_set_kernel_arg_u32.argtypes = [c_void_p, c_uint32, c_uint32, c_uint32]
        L.vasic_enqueue_ndrange.restype = c_int
        L.vasic_enqueue_ndrange.argtypes = [c_void_p, c_uint32, c_uint32]

    def close(self) -> None:
        self._dll_dirs.clear()


def _ptr_value(value) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except Exception:
        pass
    try:
        return int(value.value)
    except Exception:
        return 0


def build_vm_descriptor(*, flags: int, dataset_items: int, cache_ptr: int, dataset_ptr: int, vm_ptr: int, seed_hash: bytes) -> bytes:
    seed = bytes(seed_hash or b"")[:32].ljust(32, b"\x00")
    seed_lo = int.from_bytes(seed[:8], "little", signed=False)
    seed_hi = int.from_bytes(seed[8:16], "little", signed=False)
    return struct.pack(
        "<8Q",
        0x5641534943564D31,
        int(flags) & 0xFFFFFFFFFFFFFFFF,
        int(dataset_items) & 0xFFFFFFFFFFFFFFFF,
        int(cache_ptr) & 0xFFFFFFFFFFFFFFFF,
        int(dataset_ptr) & 0xFFFFFFFFFFFFFFFF,
        int(vm_ptr) & 0xFFFFFFFFFFFFFFFF,
        seed_lo,
        seed_hi,
    )


def snapshot_randomx_state(
    rx,
    *,
    vm=None,
    include_cache: bool = True,
    include_dataset: bool = False,
    include_vm_descriptor: bool = True,
    cache_bytes: int = DEFAULT_RANDOMX_CACHE_BYTES,
    dataset_bytes: int = 0,
    logger=None,
) -> Dict[str, bytes]:
    log = _logger_or_nop(logger)
    if rx is None:
        raise VirtualASICError("snapshot_randomx_state called with rx=None")

    seed = bytes(getattr(rx, "_seed", b"") or b"")
    flags = int(getattr(rx, "_flags", 0) or 0)
    dataset_items = int(getattr(rx, "_dataset_items", 0) or 0)
    cache_ptr = _ptr_value(getattr(rx, "_cache", 0))
    dataset_ptr = _ptr_value(getattr(rx, "_dataset", 0))
    vm_ptr = _ptr_value(vm)

    out: Dict[str, bytes] = {
        "seed_hash": seed,
        "cache_bytes": b"",
        "dataset_bytes": b"",
        "vm_state_bytes": b"",
    }

    global _SNAPSHOT_ALLOW_CACHE, _SNAPSHOT_ALLOW_DATASET

    if include_cache and cache_ptr and cache_bytes > 0 and _SNAPSHOT_ALLOW_CACHE:
        try:
            out["cache_bytes"] = bytes(string_at(cache_ptr, int(cache_bytes)))
            log(f"[VirtualASIC] Captured RandomX cache snapshot ({len(out['cache_bytes'])} bytes).")
        except Exception as e:
            _SNAPSHOT_ALLOW_CACHE = False
            log(f"[VirtualASIC] RandomX cache snapshot disabled after access failure: {e}")
            out["cache_bytes"] = b""

    if include_dataset and dataset_ptr and _SNAPSHOT_ALLOW_DATASET:
        bytes_to_copy = int(dataset_bytes)
        if bytes_to_copy <= 0:
            bytes_to_copy = int(dataset_items) * RANDOMX_DATASET_ITEM_BYTES
        try:
            out["dataset_bytes"] = bytes(string_at(dataset_ptr, bytes_to_copy))
            log(f"[VirtualASIC] Captured RandomX dataset snapshot ({len(out['dataset_bytes'])} bytes).")
        except Exception as e:
            _SNAPSHOT_ALLOW_DATASET = False
            log(f"[VirtualASIC] RandomX dataset snapshot disabled after access failure: {e}")
            out["dataset_bytes"] = b""

    if include_vm_descriptor:
        out["vm_state_bytes"] = build_vm_descriptor(
            flags=flags,
            dataset_items=dataset_items,
            cache_ptr=cache_ptr,
            dataset_ptr=dataset_ptr,
            vm_ptr=vm_ptr,
            seed_hash=seed,
        )

    return out


class VirtualASICScanner:
    RECORD_SIZE = 36

    def __init__(
        self,
        *,
        dll_path: str = "",
        kernel_path: str = "",
        kernel_name: str = "monero_scan",
        core_count: int = 0,
        logger=None,
        default_max_results: int = 8,
        seed_bytes: int = 32,
        initial_blob_bytes: int = 256,
        enable_randomx_state_args: bool = False,
        strict_randomx_state_args: bool = False,
        cache_arg_index: Optional[int] = 10,
        cache_bytes_arg_index: Optional[int] = 11,
        dataset_arg_index: Optional[int] = 12,
        dataset_bytes_arg_index: Optional[int] = 13,
        vm_state_arg_index: Optional[int] = 14,
        vm_state_bytes_arg_index: Optional[int] = 15,
    ) -> None:
        self.logger = _logger_or_nop(logger)
        self._dll = _VirtualASICDll(dll_path=dll_path, logger=self.logger)
        self.lib = self._dll.lib
        self._mu = threading.RLock()

        self.kernel_name = str(kernel_name or "monero_scan").strip() or "monero_scan"
        self.kernel_path = resolve_resource_path(
            kernel_path,
            env_var="VIRTUALASIC_KERNEL",
            fallback_names=(
                "randomx_scan_extended_topk.cl",
                "randomx_scan_extended.cl",
                "randomx_scan.cl",
                "monero_scan.cl",
                "virtualasic_monero_scan.cl",
                "virtualasic_monero_scan_advanced.cl",
            ),
        )
        if not self.kernel_path:
            raise VirtualASICError("No VirtualASIC kernel path resolved. Provide a kernel file path or set VIRTUALASIC_KERNEL.")

        self.default_max_results = max(1, int(default_max_results))
        self.seed_bytes = max(1, int(seed_bytes))
        self.initial_blob_bytes = max(64, int(initial_blob_bytes))

        self.enable_randomx_state_args = bool(enable_randomx_state_args)
        self.strict_randomx_state_args = bool(strict_randomx_state_args)
        self.cache_arg_index = cache_arg_index
        self.cache_bytes_arg_index = cache_bytes_arg_index
        self.dataset_arg_index = dataset_arg_index
        self.dataset_bytes_arg_index = dataset_bytes_arg_index
        self.vm_state_arg_index = vm_state_arg_index
        self.vm_state_bytes_arg_index = vm_state_bytes_arg_index
        self._randomx_args_supported: Optional[bool] = None

        self.engine = self.lib.vasic_create_ex(_u32(max(0, int(core_count))))
        if not self.engine:
            raise VirtualASICError("vasic_create_ex failed")

        self.kernel_id = c_uint32(0)
        self.buf_seed = c_uint32(0)
        self.buf_blob = c_uint32(0)
        self.buf_count = c_uint32(0)
        self.buf_results = c_uint32(0)
        self.buf_rx_cache = c_uint32(0)
        self.buf_rx_dataset = c_uint32(0)
        self.buf_rx_vm_state = c_uint32(0)
        self.buf_rx_placeholder = c_uint32(0)

        self._blob_capacity = 0
        self._result_capacity = 0
        self._rx_cache_capacity = 0
        self._rx_dataset_capacity = 0
        self._rx_vm_state_capacity = 0
        self._rx_placeholder_capacity = 0
        self._last_seed = b""
        self._last_blob = b""
        self._last_cache_blob = b""
        self._last_dataset_blob = b""
        self._last_vm_state_blob = b""
        self._bound_cache_size = 0
        self._bound_dataset_size = 0
        self._bound_vm_state_size = 0

        try:
            self._load_kernel()
            self._alloc_seed_buffer(self.seed_bytes)
            self._alloc_blob_buffer(self.initial_blob_bytes)
            self._alloc_count_buffer()
            self._alloc_results_buffer(self.default_max_results)
            self._bind_static_args()
            if self.enable_randomx_state_args:
                self._bind_extended_args(force=True)
        except Exception:
            self.close()
            raise

    def _last_error_text(self) -> str:
        if not self.engine:
            return ""
        buf = create_string_buffer(4096)
        try:
            n = int(self.lib.vasic_copy_last_error(self.engine, buf, _u32(len(buf))))
        except Exception:
            return ""
        if n <= 0:
            return ""
        try:
            return buf.value.decode("utf-8", errors="replace").strip()
        except Exception:
            return repr(buf.value)

    def _raise(self, msg: str) -> None:
        extra = self._last_error_text()
        if extra:
            raise VirtualASICError(f"{msg}: {extra}")
        raise VirtualASICError(msg)

    def _call_ok(self, ok: int, msg: str) -> None:
        if int(ok) != 1:
            self._raise(msg)

    def _log_kernel_metadata(self, path: Path) -> None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        has_mode = "@vasic_mode candidate_merge" in text
        has_count = "@vasic_count_arg 8" in text
        has_merge = "@vasic_merge_buffer 9:36" in text
        has_partition = "@vasic_partition global_offset" in text

        if has_mode and has_count and has_merge:
            self.logger("[VirtualASIC] Kernel metadata detected: candidate_merge enabled; CPU-lane build/merge can be used by the DLL.")
            if has_partition:
                self.logger("[VirtualASIC] Kernel metadata detected: global_offset partitioning enabled.")
        else:
            self.logger("[VirtualASIC] Kernel metadata warning: candidate_merge metadata not fully detected.")

    def _load_kernel(self) -> None:
        path = Path(self.kernel_path)
        if not path.exists():
            raise VirtualASICError(f"VirtualASIC kernel file not found: {path}")
        kid = int(self.lib.vasic_load_kernel_file(self.engine, self.kernel_name.encode("utf-8"), str(path).encode("utf-8")))
        if kid == 0:
            self._raise(f"vasic_load_kernel_file failed for '{path}'")
        self.kernel_id = _u32(kid)
        self.logger(f"[VirtualASIC] Kernel loaded: name={self.kernel_name} path={path}")
        self._log_kernel_metadata(path)

    def _release_buffer(self, buf_id: int) -> None:
        if self.engine and int(buf_id):
            try:
                self.lib.vasic_release_buffer(self.engine, c_uint32(int(buf_id)))
            except Exception:
                pass

    def _alloc_buffer(self, size_bytes: int) -> c_uint32:
        bid = int(self.lib.vasic_create_buffer(self.engine, _u32(size_bytes)))
        if bid == 0:
            self._raise(f"vasic_create_buffer({size_bytes}) failed")
        return _u32(bid)

    def _alloc_seed_buffer(self, size_bytes: int) -> None:
        if int(self.buf_seed.value):
            self._release_buffer(int(self.buf_seed.value))
        self.buf_seed = self._alloc_buffer(size_bytes)

    def _alloc_blob_buffer(self, size_bytes: int) -> None:
        size_bytes = max(64, int(size_bytes))
        if int(self.buf_blob.value):
            self._release_buffer(int(self.buf_blob.value))
        self.buf_blob = self._alloc_buffer(size_bytes)
        self._blob_capacity = size_bytes

    def _alloc_count_buffer(self) -> None:
        if int(self.buf_count.value):
            self._release_buffer(int(self.buf_count.value))
        self.buf_count = self._alloc_buffer(4)

    def _alloc_results_buffer(self, max_results: int) -> None:
        max_results = max(1, int(max_results))
        bytes_needed = max_results * self.RECORD_SIZE
        if int(self.buf_results.value):
            self._release_buffer(int(self.buf_results.value))
        self.buf_results = self._alloc_buffer(bytes_needed)
        self._result_capacity = max_results

    def _ensure_randomx_buffer(self, which: str, size_bytes: int) -> c_uint32:
        size_bytes = max(1, int(size_bytes))
        if which == "cache":
            if size_bytes <= self._rx_cache_capacity and int(self.buf_rx_cache.value):
                return self.buf_rx_cache
            if int(self.buf_rx_cache.value):
                self._release_buffer(int(self.buf_rx_cache.value))
            self.buf_rx_cache = self._alloc_buffer(size_bytes)
            self._rx_cache_capacity = size_bytes
            self._randomx_args_supported = None
            return self.buf_rx_cache

        if which == "dataset":
            if size_bytes <= self._rx_dataset_capacity and int(self.buf_rx_dataset.value):
                return self.buf_rx_dataset
            if int(self.buf_rx_dataset.value):
                self._release_buffer(int(self.buf_rx_dataset.value))
            self.buf_rx_dataset = self._alloc_buffer(size_bytes)
            self._rx_dataset_capacity = size_bytes
            self._randomx_args_supported = None
            return self.buf_rx_dataset

        if which == "vm_state":
            if size_bytes <= self._rx_vm_state_capacity and int(self.buf_rx_vm_state.value):
                return self.buf_rx_vm_state
            if int(self.buf_rx_vm_state.value):
                self._release_buffer(int(self.buf_rx_vm_state.value))
            self.buf_rx_vm_state = self._alloc_buffer(size_bytes)
            self._rx_vm_state_capacity = size_bytes
            self._randomx_args_supported = None
            return self.buf_rx_vm_state

        raise VirtualASICError(f"Unknown RandomX buffer kind: {which}")

    def _ensure_placeholder_buffer(self, size_bytes: int = 4) -> c_uint32:
        need = max(1, int(size_bytes))
        if need <= self._rx_placeholder_capacity and int(self.buf_rx_placeholder.value):
            return self.buf_rx_placeholder
        if int(self.buf_rx_placeholder.value):
            self._release_buffer(int(self.buf_rx_placeholder.value))
            self.buf_rx_placeholder = c_uint32(0)
            self._rx_placeholder_capacity = 0
        self.buf_rx_placeholder = self._alloc_buffer(need)
        self._rx_placeholder_capacity = need
        self._write_buffer(int(self.buf_rx_placeholder.value), b"\x00" * need)
        self._randomx_args_supported = None
        return self.buf_rx_placeholder

    def _get_bound_randomx_buffer(self, which: str) -> c_uint32:
        if which == "cache":
            return self.buf_rx_cache if int(self.buf_rx_cache.value) else self._ensure_placeholder_buffer()
        if which == "dataset":
            return self.buf_rx_dataset if int(self.buf_rx_dataset.value) else self._ensure_placeholder_buffer()
        if which == "vm_state":
            return self.buf_rx_vm_state if int(self.buf_rx_vm_state.value) else self._ensure_placeholder_buffer()
        raise VirtualASICError(f"Unknown RandomX buffer kind: {which}")

    def _bind_static_args(self) -> None:
        self._call_ok(self.lib.vasic_set_kernel_arg_buffer(self.engine, self.kernel_id, c_uint32(0), self.buf_seed), "bind arg0 seed buffer failed")
        self._call_ok(self.lib.vasic_set_kernel_arg_buffer(self.engine, self.kernel_id, c_uint32(1), self.buf_blob), "bind arg1 blob buffer failed")
        self._call_ok(self.lib.vasic_set_kernel_arg_buffer(self.engine, self.kernel_id, c_uint32(8), self.buf_count), "bind arg8 count buffer failed")
        self._call_ok(self.lib.vasic_set_kernel_arg_buffer(self.engine, self.kernel_id, c_uint32(9), self.buf_results), "bind arg9 results buffer failed")
        if self.enable_randomx_state_args:
            self._bind_extended_args(force=True)

    def _bind_extended_args(self, force: bool = False) -> bool:
        if not self.enable_randomx_state_args:
            return False
        if self._randomx_args_supported is True and not force:
            return True

        cache_buf = self._get_bound_randomx_buffer("cache")
        dataset_buf = self._get_bound_randomx_buffer("dataset")
        vm_buf = self._get_bound_randomx_buffer("vm_state")

        self._call_ok(self.lib.vasic_set_kernel_arg_buffer(self.engine, self.kernel_id, _u32(int(self.cache_arg_index)), cache_buf), f"bind arg{self.cache_arg_index} cache buffer failed")
        self._call_ok(self.lib.vasic_set_kernel_arg_u32(self.engine, self.kernel_id, _u32(int(self.cache_bytes_arg_index)), _u32(int(self._bound_cache_size))), f"set arg{self.cache_bytes_arg_index} cache size failed")
        self._call_ok(self.lib.vasic_set_kernel_arg_buffer(self.engine, self.kernel_id, _u32(int(self.dataset_arg_index)), dataset_buf), f"bind arg{self.dataset_arg_index} dataset buffer failed")
        self._call_ok(self.lib.vasic_set_kernel_arg_u32(self.engine, self.kernel_id, _u32(int(self.dataset_bytes_arg_index)), _u32(int(self._bound_dataset_size))), f"set arg{self.dataset_bytes_arg_index} dataset size failed")
        self._call_ok(self.lib.vasic_set_kernel_arg_buffer(self.engine, self.kernel_id, _u32(int(self.vm_state_arg_index)), vm_buf), f"bind arg{self.vm_state_arg_index} vm-state buffer failed")
        self._call_ok(self.lib.vasic_set_kernel_arg_u32(self.engine, self.kernel_id, _u32(int(self.vm_state_bytes_arg_index)), _u32(int(self._bound_vm_state_size))), f"set arg{self.vm_state_bytes_arg_index} vm-state size failed")
        self._randomx_args_supported = True
        return True

    def _ensure_blob_capacity(self, n: int) -> None:
        if n <= self._blob_capacity and int(self.buf_blob.value):
            return
        self._alloc_blob_buffer(max(n, self._blob_capacity * 2 if self._blob_capacity else self.initial_blob_bytes))
        self._bind_static_args()
        if self._last_blob:
            self._write_buffer(int(self.buf_blob.value), self._last_blob)

    def _ensure_results_capacity(self, max_results: int) -> None:
        if max_results <= self._result_capacity and int(self.buf_results.value):
            return
        self._alloc_results_buffer(max_results)
        self._bind_static_args()

    def _write_buffer(self, buffer_id: int, data: bytes, offset: int = 0) -> None:
        payload = bytes(data or b"")
        if not payload:
            return
        arr = create_string_buffer(payload, len(payload))
        ptr = _as_void_p_from_buffer(arr)
        self._call_ok(self.lib.vasic_write_buffer(self.engine, _u32(buffer_id), _u32(offset), ptr, _u32(len(payload))), f"write buffer {buffer_id} failed")

    def _read_buffer(self, buffer_id: int, size_bytes: int, offset: int = 0) -> bytes:
        out = create_string_buffer(int(size_bytes))
        ptr = _as_void_p_from_buffer(out)
        self._call_ok(self.lib.vasic_read_buffer(self.engine, _u32(buffer_id), _u32(offset), ptr, _u32(size_bytes)), f"read buffer {buffer_id} failed")
        return bytes(out.raw)

    def _set_u32(self, arg_index: int, value: int) -> None:
        self._call_ok(self.lib.vasic_set_kernel_arg_u32(self.engine, self.kernel_id, _u32(arg_index), _u32(value)), f"set arg{arg_index} failed")

    def upload_randomx_state(self, *, cache_bytes: bytes = b"", dataset_bytes: bytes = b"", vm_state_bytes: bytes = b"") -> bool:
        with self._mu:
            cache_payload = bytes(cache_bytes or b"")
            dataset_payload = bytes(dataset_bytes or b"")
            vm_payload = bytes(vm_state_bytes or b"")

            if cache_payload:
                self._ensure_randomx_buffer("cache", len(cache_payload))
                if cache_payload != self._last_cache_blob:
                    self._write_buffer(int(self.buf_rx_cache.value), cache_payload)
                    self._last_cache_blob = cache_payload

            if dataset_payload:
                self._ensure_randomx_buffer("dataset", len(dataset_payload))
                if dataset_payload != self._last_dataset_blob:
                    self._write_buffer(int(self.buf_rx_dataset.value), dataset_payload)
                    self._last_dataset_blob = dataset_payload

            if vm_payload:
                self._ensure_randomx_buffer("vm_state", len(vm_payload))
                if vm_payload != self._last_vm_state_blob:
                    self._write_buffer(int(self.buf_rx_vm_state.value), vm_payload)
                    self._last_vm_state_blob = vm_payload

            self._bound_cache_size = len(cache_payload)
            self._bound_dataset_size = len(dataset_payload)
            self._bound_vm_state_size = len(vm_payload)
            self._bind_extended_args(force=True)
            return True

    def scan_sync(self, *, seed_hash: bytes, blob: bytes, nonce_offset: int, start_nonce: int, iters: int, target64: int, max_results: Optional[int] = None) -> Dict[str, object]:
        seed_hash = bytes(seed_hash or b"")
        blob = bytes(blob or b"")
        if not seed_hash:
            raise VirtualASICError("seed_hash is empty")
        if not blob:
            raise VirtualASICError("blob is empty")

        result_cap = max(1, int(max_results or self.default_max_results))

        with self._mu:
            self._ensure_blob_capacity(len(blob))
            self._ensure_results_capacity(result_cap)

            if seed_hash != self._last_seed:
                seed_payload = seed_hash[: self.seed_bytes].ljust(self.seed_bytes, b"\x00")
                self._write_buffer(int(self.buf_seed.value), seed_payload)
                self._last_seed = bytes(seed_hash)

            if blob != self._last_blob:
                self._write_buffer(int(self.buf_blob.value), blob)
                self._last_blob = bytes(blob)

            self._write_buffer(int(self.buf_count.value), (0).to_bytes(4, "little", signed=False))
            self._write_buffer(int(self.buf_results.value), b"\x00" * (result_cap * self.RECORD_SIZE))

            self._set_u32(2, len(blob))
            self._set_u32(3, int(nonce_offset))
            self._set_u32(4, int(start_nonce))
            self._set_u32(5, int(target64) & 0xFFFFFFFF)
            self._set_u32(6, (int(target64) >> 32) & 0xFFFFFFFF)
            self._set_u32(7, result_cap)
            if self.enable_randomx_state_args:
                self._bind_extended_args(force=True)

            self._call_ok(self.lib.vasic_enqueue_ndrange(self.engine, self.kernel_id, _u32(max(1, int(iters)))), "vasic_enqueue_ndrange failed")

            count_raw = self._read_buffer(int(self.buf_count.value), 4)
            found_count = int.from_bytes(count_raw[:4], "little", signed=False)
            found_count = max(0, min(found_count, result_cap))

            found: List[Dict[str, object]] = []
            if found_count > 0:
                raw = self._read_buffer(int(self.buf_results.value), found_count * self.RECORD_SIZE)
                for i in range(found_count):
                    off = i * self.RECORD_SIZE
                    rec = raw[off : off + self.RECORD_SIZE]
                    if len(rec) != self.RECORD_SIZE:
                        break
                    nonce_u32 = int.from_bytes(rec[0:4], "little", signed=False)
                    hash32 = rec[4:36]
                    if len(hash32) != 32:
                        continue
                    found.append({"nonce_u32": nonce_u32, "hash_hex": hash32.hex()})

            return {"hashes_done": max(1, int(iters)), "found": found, "start_nonce": int(start_nonce) & 0xFFFFFFFF, "iters": max(1, int(iters))}

    def close(self) -> None:
        with self._mu:
            if self.engine:
                try:
                    if int(self.kernel_id.value):
                        try:
                            self.lib.vasic_release_kernel(self.engine, self.kernel_id)
                        except Exception:
                            pass
                        self.kernel_id = c_uint32(0)

                    for buf in (
                        self.buf_seed, self.buf_blob, self.buf_count, self.buf_results,
                        self.buf_rx_cache, self.buf_rx_dataset, self.buf_rx_vm_state, self.buf_rx_placeholder,
                    ):
                        if int(buf.value):
                            try:
                                self.lib.vasic_release_buffer(self.engine, buf)
                            except Exception:
                                pass

                    self.buf_seed = c_uint32(0)
                    self.buf_blob = c_uint32(0)
                    self.buf_count = c_uint32(0)
                    self.buf_results = c_uint32(0)
                    self.buf_rx_cache = c_uint32(0)
                    self.buf_rx_dataset = c_uint32(0)
                    self.buf_rx_vm_state = c_uint32(0)
                    self.buf_rx_placeholder = c_uint32(0)
                finally:
                    try:
                        self.lib.vasic_destroy(self.engine)
                    except Exception:
                        pass
                    self.engine = c_void_p()
            self._dll.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
