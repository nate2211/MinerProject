from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ctypes import c_ubyte, c_uint32, c_uint64, POINTER, byref, cast, memmove
from dataclasses import dataclass
from typing import Callable, Optional

from monero_job import MoneroJob
from randomx_ctypes import RandomX


@dataclass(frozen=True)
class ScanShare:
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
class ScanStats:
    hashes_done: int
    shares_found: int
    elapsed_sec: float


class _ThreadVMState(threading.local):
    def __init__(self) -> None:
        super().__init__()
        self.seed_hash: bytes = b""
        self.vm = None
        self.blob_buf = None
        self.nonce_ptr = None
        self.out_buf = None


class ParallelMoneroScanner:
    """
    Parallel local RandomX scanner.

    Important behavior:
      - shared dataset/cache in one process
      - one VM per executor thread
      - scan_sync() works in waves so hashes_done returns promptly
      - shares are real full RandomX results below target64
    """

    def __init__(
        self,
        *,
        threads: int = 1,
        logger: Optional[Callable[[str], None]] = None,
        randomx: Optional[RandomX] = None,
        executor: Optional[ThreadPoolExecutor] = None,
        chunk_size: int = 8192,
        max_results_per_chunk: int = 32,
    ) -> None:
        self.logger = logger or (lambda s: None)
        self.threads = max(1, int(threads))
        self.chunk_size = max(1, int(chunk_size))
        self.max_results_per_chunk = max(1, int(max_results_per_chunk))

        self.rx = randomx or RandomX(self.logger)
        self._own_executor = executor is None
        self._executor = executor or ThreadPoolExecutor(
            max_workers=self.threads,
            thread_name_prefix="pp-monero",
        )

        self._tls = _ThreadVMState()
        self._seed_lock = threading.RLock()
        self._prepared_seed: bytes = b""
        self._stop = threading.Event()
        self._closed = False

    def close(self) -> None:
        self._stop.set()
        self._closed = True
        if self._own_executor and self._executor is not None:
            self._executor.shutdown(wait=True, cancel_futures=False)

    def stop(self) -> None:
        self._stop.set()

    def reset_stop(self) -> None:
        self._stop.clear()

    def ensure_seed(self, seed_hash: bytes) -> None:
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        with self._seed_lock:
            if seed_hash == self._prepared_seed:
                return
            self.logger("[ParallelMoneroScanner] Preparing RandomX seed...")
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

    def _scan_nonce_range(
        self,
        *,
        job: MoneroJob,
        start_nonce: int,
        count: int,
        max_results: int,
    ) -> tuple[list[ScanShare], int]:
        self._ensure_thread_vm(job)
        st = self._tls

        shares: list[ScanShare] = []
        hashes_done = 0
        target64 = int(job.target64) & 0xFFFFFFFFFFFFFFFF
        rx_hash_into = self.rx.hash_into

        for i in range(max(0, int(count))):
            if self._stop.is_set():
                break

            nonce_u32 = (int(start_nonce) + i) & 0xFFFFFFFF
            st.nonce_ptr[0] = nonce_u32
            rx_hash_into(st.vm, st.blob_buf, st.out_buf)
            hashes_done += 1

            tail64 = c_uint64.from_buffer(st.out_buf, 24).value
            if tail64 < target64:
                shares.append(
                    ScanShare(
                        job_id=job.job_id,
                        nonce_u32=nonce_u32,
                        result32=bytes(st.out_buf),
                    )
                )
                if len(shares) >= max_results:
                    break

        return shares, hashes_done

    def _build_wave(self, start_nonce: int, remaining: int) -> list[tuple[int, int]]:
        wave: list[tuple[int, int]] = []
        cur = int(start_nonce) & 0xFFFFFFFF
        left = max(0, int(remaining))

        for _ in range(self.threads):
            if left <= 0:
                break
            take = min(self.chunk_size, left)
            wave.append((cur, take))
            cur = (cur + take) & 0xFFFFFFFF
            left -= take

        return wave

    def scan_sync(
        self,
        *,
        job: MoneroJob,
        start_nonce: int,
        iters: int,
        max_results: int = 8,
    ) -> dict:
        if self._closed:
            raise RuntimeError("ParallelMoneroScanner is closed")

        total_iters = max(0, int(iters))
        if total_iters <= 0:
            return {
                "job_id": job.job_id,
                "hashes_done": 0,
                "found": [],
                "elapsed_sec": 0.0,
            }

        t0 = time.perf_counter()
        self.ensure_seed(job.seed_hash)
        self.reset_stop()

        wanted_results = max(1, int(max_results))
        per_chunk_cap = min(wanted_results, self.max_results_per_chunk)

        hashes_done = 0
        found: list[dict] = []

        next_nonce = int(start_nonce) & 0xFFFFFFFF
        remaining = total_iters

        try:
            while remaining > 0 and not self._stop.is_set():
                wave = self._build_wave(next_nonce, remaining)
                if not wave:
                    break

                scheduled = sum(cnt for _, cnt in wave)

                futures = [
                    self._executor.submit(
                        self._scan_nonce_range,
                        job=job,
                        start_nonce=chunk_start,
                        count=chunk_count,
                        max_results=per_chunk_cap,
                    )
                    for chunk_start, chunk_count in wave
                ]

                for fut in as_completed(futures):
                    shares, done = fut.result()
                    hashes_done += int(done)

                    for share in shares:
                        found.append(
                            {
                                "nonce_u32": int(share.nonce_u32),
                                "hash_hex": share.result_hex,
                            }
                        )
                        if len(found) >= wanted_results:
                            self._stop.set()
                            break

                    if self._stop.is_set():
                        break

                next_nonce = (next_nonce + scheduled) & 0xFFFFFFFF
                remaining -= scheduled

        finally:
            self._stop.clear()

        elapsed = time.perf_counter() - t0
        return {
            "job_id": job.job_id,
            "hashes_done": int(hashes_done),
            "found": found[:wanted_results],
            "elapsed_sec": float(elapsed),
        }

    def iter_scan_forever(
        self,
        *,
        job_supplier: Callable[[], Optional[MoneroJob]],
        nonce_allocator: Callable[[int], int],
        iters_per_scan: int = 100_000,
        max_results: int = 8,
        on_share: Optional[Callable[[ScanShare], None]] = None,
        on_stats: Optional[Callable[[ScanStats], None]] = None,
        sleep_when_idle: float = 0.05,
    ) -> None:
        while not self._stop.is_set():
            job = job_supplier()
            if job is None:
                time.sleep(max(0.0, float(sleep_when_idle)))
                continue

            start_nonce = nonce_allocator(int(iters_per_scan))
            resp = self.scan_sync(
                job=job,
                start_nonce=start_nonce,
                iters=iters_per_scan,
                max_results=max_results,
            )

            found = resp.get("found") or []
            hashes_done = int(resp.get("hashes_done") or 0)
            elapsed_sec = float(resp.get("elapsed_sec") or 0.0)

            if on_stats is not None:
                on_stats(
                    ScanStats(
                        hashes_done=hashes_done,
                        shares_found=len(found),
                        elapsed_sec=elapsed_sec,
                    )
                )

            if on_share is not None:
                for one in found:
                    try:
                        share = ScanShare(
                            job_id=job.job_id,
                            nonce_u32=int(one["nonce_u32"]),
                            result32=bytes.fromhex(str(one["hash_hex"])),
                        )
                        on_share(share)
                    except Exception:
                        continue