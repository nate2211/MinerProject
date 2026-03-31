from __future__ import annotations

import os
import sys
import threading
import time
from ctypes import (
    CDLL, c_int, c_void_p, c_size_t, c_uint64, c_ubyte, POINTER, byref, create_string_buffer,addressof, c_void_p
)
from ctypes.util import find_library

RANDOMX_FLAG_DEFAULT      = 0
RANDOMX_FLAG_LARGE_PAGES  = 1 << 0
RANDOMX_FLAG_HARD_AES     = 1 << 1
RANDOMX_FLAG_FULL_MEM     = 1 << 2
RANDOMX_FLAG_JIT          = 1 << 3
RANDOMX_FLAG_SECURE       = 1 << 4

class RandomX:
    def __init__(
        self,
        logger=None,
        *,
        use_large_pages: bool = True,
        use_full_mem: bool = True,
        use_jit: bool = True,
        use_hard_aes: bool = True,
        use_secure_jit: bool = False,
    ) -> None:
        self.logger = logger or (lambda s: None)
        self.logger("[RandomX] Loading DLL...")
        self.lib = self._load_randomx()
        self.logger(f"[RandomX] DLL Loaded: {self.lib}")

        self._bind()

        self._lock = threading.RLock()
        self._seed: bytes = b""

        base_flags = int(self.randomx_get_flags())
        flags = int(base_flags)

        # randomx_get_flags() does not include LARGE_PAGES / FULL_MEM / SECURE automatically
        if use_large_pages:
            flags |= RANDOMX_FLAG_LARGE_PAGES
        if use_full_mem:
            flags |= RANDOMX_FLAG_FULL_MEM
        if use_jit:
            flags |= RANDOMX_FLAG_JIT
        if use_hard_aes:
            flags |= RANDOMX_FLAG_HARD_AES
        if use_secure_jit:
            flags |= RANDOMX_FLAG_SECURE

        self._base_flags = base_flags
        self._flags = flags

        self._cache = None
        self._dataset = None
        self._dataset_items = int(self.randomx_dataset_item_count())

        self.logger(
            f"[RandomX] Base Flags: {self._base_flags} | Active Flags: {self._flags} "
            f"(large_pages={use_large_pages}, full_mem={use_full_mem}, "
            f"jit={use_jit}, hard_aes={use_hard_aes}, secure_jit={use_secure_jit})"
        )
        self.logger(f"[RandomX] Dataset Items: {self._dataset_items}")

    def _load_randomx(self) -> CDLL:
        # 1. Try environment variable
        env = os.environ.get("RANDOMX_LIB", "").strip()
        if env:
            try:
                return CDLL(env)
            except Exception as e:
                self.logger(f"[RandomX] Warning: Could not load from RANDOMX_LIB={env}: {e}")

        # 2. Try common names
        candidates = ["./randomx-dll.dll", "randomx.dll", "librandomx.so", "librandomx.dylib"]

        # 3. Try system path
        sys_lib = find_library("randomx")
        if sys_lib:
            candidates.append(sys_lib)

        for c in candidates:
            try:
                return CDLL(c)
            except Exception:
                pass

        raise RuntimeError("FATAL: Could not find randomx.dll. Please ensure it is in the same folder.")

    def _bind(self) -> None:
        L = self.lib

        # --- 1. Set Return Types (restype) ---
        # Tells ctypes that these functions return Pointers (memory addresses), not 32-bit ints
        L.randomx_get_flags.restype = c_int
        L.randomx_alloc_cache.restype = c_void_p
        L.randomx_alloc_dataset.restype = c_void_p
        L.randomx_dataset_item_count.restype = c_uint64
        L.randomx_create_vm.restype = c_void_p

        # --- 2. Map functions ---
        self.randomx_get_flags = L.randomx_get_flags
        self.randomx_alloc_cache = L.randomx_alloc_cache
        self.randomx_init_cache = L.randomx_init_cache
        self.randomx_release_cache = L.randomx_release_cache
        self.randomx_alloc_dataset = L.randomx_alloc_dataset
        self.randomx_dataset_item_count = L.randomx_dataset_item_count
        self.randomx_init_dataset = L.randomx_init_dataset
        self.randomx_release_dataset = L.randomx_release_dataset
        self.randomx_create_vm = L.randomx_create_vm
        self.randomx_destroy_vm = L.randomx_destroy_vm
        self.randomx_calculate_hash = L.randomx_calculate_hash

        # --- 3. CRITICAL: Set Argument Types (argtypes) ---
        # This fixes the "OverflowError". We must explicitly tell ctypes
        # that these arguments are Pointers (c_void_p), otherwise it assumes they are 32-bit ints.

        self.randomx_alloc_cache.argtypes = [c_int]
        self.randomx_init_cache.argtypes = [c_void_p, c_void_p, c_size_t]
        self.randomx_release_cache.argtypes = [c_void_p]

        self.randomx_alloc_dataset.argtypes = [c_int]
        self.randomx_init_dataset.argtypes = [c_void_p, c_void_p, c_uint64, c_uint64]
        self.randomx_release_dataset.argtypes = [c_void_p]

        # This was the specific line causing your crash:
        self.randomx_create_vm.argtypes = [c_int, c_void_p, c_void_p]

        self.randomx_destroy_vm.argtypes = [c_void_p]
        self.randomx_calculate_hash.argtypes = [c_void_p, c_void_p, c_size_t, c_void_p]

    def ensure_seed(self, seed_hash: bytes) -> None:
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        with self._lock:
            if seed_hash == self._seed and self._cache is not None and self._dataset is not None:
                return

            self.logger("[RandomX] New Seed Detected! Initializing Dataset...")
            t0 = time.time()

            if self._dataset is not None:
                self.randomx_release_dataset(self._dataset)
                self._dataset = None
            if self._cache is not None:
                self.randomx_release_cache(self._cache)
                self._cache = None

            seed_buf = (c_ubyte * len(seed_hash)).from_buffer_copy(seed_hash)

            flags_try = [self._flags]
            if self._flags & RANDOMX_FLAG_LARGE_PAGES:
                flags_try.append(self._flags & ~RANDOMX_FLAG_LARGE_PAGES)

            last_err = None
            for flags in flags_try:
                try:
                    cache = self.randomx_alloc_cache(flags)
                    if not cache:
                        raise MemoryError(f"randomx_alloc_cache failed (flags={flags})")

                    self.randomx_init_cache(cache, seed_buf, c_size_t(len(seed_hash)))

                    dataset = self.randomx_alloc_dataset(flags)
                    if not dataset:
                        self.randomx_release_cache(cache)
                        raise MemoryError(f"randomx_alloc_dataset failed (flags={flags})")

                    self.logger(f"[RandomX] Building Dataset... flags={flags}")
                    self.randomx_init_dataset(dataset, cache, c_uint64(0), c_uint64(self._dataset_items))

                    self._cache = cache
                    self._dataset = dataset
                    self._seed = seed_hash
                    self._active_seed_flags = flags

                    dt = time.time() - t0
                    self.logger(f"[RandomX] Dataset Ready! flags={flags} took {dt:.2f}s")
                    return

                except Exception as e:
                    last_err = e
                    self.logger(f"[RandomX] Seed init attempt failed with flags={flags}: {type(e).__name__}: {e}")

            raise last_err

    def create_vm(self) -> c_void_p:
        with self._lock:
            if self._cache is None or self._dataset is None:
                raise RuntimeError("seed not initialized")

            vm = self.randomx_create_vm(self._active_seed_flags, self._cache, self._dataset)
            if not vm:
                raise RuntimeError(f"randomx_create_vm returned NULL (flags={self._active_seed_flags})")

            return vm

    def destroy_vm(self, vm: c_void_p) -> None:
        try:
            if vm:
                self.randomx_destroy_vm(vm)
        except Exception:
            pass

    def hash(self, vm: c_void_p, data: bytes) -> bytes:
        out = create_string_buffer(32)
        buf = (c_ubyte * len(data)).from_buffer_copy(data)
        self.randomx_calculate_hash(vm, buf, c_size_t(len(data)), out)
        return out.raw

    def hash_into(self, vm, blob_buf, out32_buf) -> None:
        # out32_buf must be a (c_ubyte * 32) or compatible writable buffer
        self.randomx_calculate_hash(vm, blob_buf, len(blob_buf), out32_buf)