from __future__ import annotations

import os
import sys
import threading
import time
from ctypes import (
    CDLL, c_int, c_void_p, c_size_t, c_uint64, c_ubyte, POINTER, byref, create_string_buffer,addressof, c_void_p
)
from ctypes.util import find_library


class RandomX:
    def __init__(self, logger = None) -> None:
        self.logger = logger
        self.logger("[RandomX] Loading DLL...")
        self.lib = self._load_randomx()
        self.logger(f"[RandomX] DLL Loaded: {self.lib}")

        self._bind()

        self._lock = threading.RLock()
        self._seed: bytes = b""
        self._flags: int = int(self.randomx_get_flags())

        # Initialize as None so we can safely check "is not None"
        self._cache = None
        self._dataset = None

        self._dataset_items: int = int(self.randomx_dataset_item_count())
        self.logger(f"[RandomX] Flags: {self._flags}, Dataset Items: {self._dataset_items}")

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

            self.logger(f"[RandomX] New Seed Detected! Initializing Dataset (this takes time)...")
            t0 = time.time()

            if self._dataset is not None:
                self.randomx_release_dataset(self._dataset)
                self._dataset = None
            if self._cache is not None:
                self.randomx_release_cache(self._cache)
                self._cache = None

            self._cache = self.randomx_alloc_cache(self._flags)
            if not self._cache:
                raise MemoryError("Failed to allocate RandomX Cache")

            seed_buf = (c_ubyte * len(seed_hash)).from_buffer_copy(seed_hash)
            self.randomx_init_cache(self._cache, seed_buf, c_size_t(len(seed_hash)))

            self._dataset = self.randomx_alloc_dataset(self._flags)
            if not self._dataset:
                raise MemoryError("Failed to allocate RandomX Dataset (Do you have 3GB+ RAM free?)")

            self.logger(f"[RandomX] Building Dataset... (Please Wait)")
            self.randomx_init_dataset(self._dataset, self._cache, c_uint64(0), c_uint64(self._dataset_items))

            self._seed = seed_hash
            dt = time.time() - t0
            self.logger(f"[RandomX] Dataset Ready! (Took {dt:.2f} seconds)")

    def create_vm(self) -> c_void_p:
        with self._lock:
            if self._cache is None or self._dataset is None:
                raise RuntimeError("seed not initialized")

            # Now that argtypes are set, this will pass the pointer correctly
            vm = self.randomx_create_vm(self._flags, self._cache, self._dataset)
            if not vm:
                raise RuntimeError("randomx_create_vm returned NULL")
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
