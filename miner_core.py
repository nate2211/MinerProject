from __future__ import annotations

import asyncio
import queue
import secrets
import threading
import time
import traceback
from ctypes import c_uint32, c_ubyte, byref, POINTER, cast, memmove, c_uint64
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple, List

from monero_job import MoneroJob
from randomx_ctypes import RandomX
from stratum_client import StratumClient, StratumDisconnected
from virtualasic import (
    VirtualASICError,
    VirtualASICScanner,
    snapshot_randomx_state,
)
from blocknet_mining_backend import (
    BlockNetApiCfg,
    BlockNetP2PoolBackend,
    BlockNetRandomXHasher,
    BlockNetGpuScanner,
    BlockNetCpuScanner,
)
from parallel_python_worker import ParallelMoneroScanner


@dataclass
class Share:
    job_id: str
    nonce_u32: int
    result32: bytes

    @property
    def nonce_hex(self) -> str:
        return int(self.nonce_u32).to_bytes(4, "little", signed=False).hex()

    @property
    def result_hex(self) -> str:
        return (self.result32 or b"").hex()


class JobState:
    def __init__(self) -> None:
        self._mu = threading.Lock()
        self._cv = threading.Condition(self._mu)
        self._job: Optional[MoneroJob] = None
        self._seq = 0
        self._nonce_cursor = secrets.randbits(32)

    def set(self, job: MoneroJob) -> None:
        with self._cv:
            self._job = job
            self._seq += 1
            self._nonce_cursor = secrets.randbits(32)
            self._cv.notify_all()

    def wait(self, last_seq: int, timeout: float = 0.5) -> Tuple[int, Optional[MoneroJob]]:
        with self._cv:
            if self._seq == last_seq:
                self._cv.wait(timeout=timeout)
            return self._seq, self._job

    def wake_all(self) -> None:
        with self._cv:
            self._cv.notify_all()

    def get(self) -> Optional[MoneroJob]:
        with self._mu:
            return self._job

    def alloc_nonce_block(self, n: int) -> int:
        n = max(1, int(n))
        with self._mu:
            start = self._nonce_cursor & 0xFFFFFFFF
            self._nonce_cursor = (self._nonce_cursor + n) & 0xFFFFFFFF
            return start

    @property
    def seq(self) -> int:
        return self._seq


class Miner:
    def __init__(
        self,
        *,
        stratum_host: str,
        stratum_port: int,
        wallet: str,
        password: str,
        threads: int = 1,
        agent: str = "py-blockminer/1.0",
        logger: Optional[Callable[[str], None]] = None,
        use_blocknet_p2pool: bool = False,
        use_blocknet_randomx: bool = False,
        use_blocknet_p2pool_scan: bool = False,
        use_blocknet_randomx_scan: bool = False,
        use_blocknet_gpu_scan: bool = False,
        use_blocknet_cpu_scan: bool = False,
        use_virtualasic_scan: bool = False,
        virtualasic_dll: str = "",
        virtualasic_kernel: str = "",
        virtualasic_kernel_name: str = "monero_scan",
        virtualasic_core_count: int = 0,
        virtualasic_cpu_assist: bool = False,
        virtualasic_cpu_assist_batch: int = 256,
        virtualasic_cpu_assist_max_batch: int = 2048,
        virtualasic_stage_randomx_cache: bool = False,
        virtualasic_stage_randomx_dataset: bool = False,
        virtualasic_stage_vm_descriptor: bool = True,
        virtualasic_randomx_cache_bytes: int = 256 * 1024 * 1024,
        virtualasic_randomx_dataset_bytes: int = 0,
        blocknet_api_relay: str = "",
        blocknet_api_token: str = "",
        blocknet_api_prefix: str = "/v1",
        blocknet_verify_tls: bool = False,
        randomx_batch_size: int = 64,
        submit_workers: int = 1,
        scan_iters: int = 1000,
        scan_max_results: int = 4,
        scan_poll_first: bool = False,
        scan_nonce_offset: Optional[int] = None,
        cpu_scan_threads: Optional[int] = None,
        use_parallel_monero_scan: bool = False,
        parallel_monero_threads: Optional[int] = None,
        parallel_monero_chunk_size: int = 8192,
        parallel_monero_max_results_per_chunk: int = 32,
    ) -> None:
        self.logger = logger or (lambda s: None)

        self.stratum_host = stratum_host
        self.stratum_port = int(stratum_port)
        self.wallet = wallet
        self.password = password
        self.threads = max(1, int(threads))
        self.agent = agent

        self.use_blocknet_p2pool = bool(use_blocknet_p2pool)
        self.use_blocknet_randomx = bool(use_blocknet_randomx)
        self.use_blocknet_p2pool_scan = bool(use_blocknet_p2pool_scan)
        self.use_blocknet_randomx_scan = bool(use_blocknet_randomx_scan)
        self.use_blocknet_gpu_scan = bool(use_blocknet_gpu_scan)
        self.use_blocknet_cpu_scan = bool(use_blocknet_cpu_scan)
        self.use_virtualasic_scan = bool(use_virtualasic_scan)
        self.use_parallel_monero_scan = bool(use_parallel_monero_scan)

        self.virtualasic_dll = str(virtualasic_dll or "").strip()
        self.virtualasic_kernel = str(virtualasic_kernel or "").strip()
        self.virtualasic_kernel_name = str(virtualasic_kernel_name or "monero_scan").strip() or "monero_scan"
        self.virtualasic_core_count = max(0, int(virtualasic_core_count))

        self.virtualasic_cpu_assist = bool(virtualasic_cpu_assist)
        self.virtualasic_cpu_assist_batch = max(1, int(virtualasic_cpu_assist_batch))
        self.virtualasic_cpu_assist_max_batch = max(1, int(virtualasic_cpu_assist_max_batch))

        self.virtualasic_stage_randomx_cache = bool(virtualasic_stage_randomx_cache)
        self.virtualasic_stage_randomx_dataset = bool(virtualasic_stage_randomx_dataset)
        self.virtualasic_stage_vm_descriptor = bool(virtualasic_stage_vm_descriptor)
        self.virtualasic_randomx_cache_bytes = max(0, int(virtualasic_randomx_cache_bytes))
        self.virtualasic_randomx_dataset_bytes = max(0, int(virtualasic_randomx_dataset_bytes))

        self.scan_iters = max(1, int(scan_iters))
        self.scan_max_results = max(1, int(scan_max_results))
        self.scan_poll_first = bool(scan_poll_first)
        self.scan_nonce_offset = scan_nonce_offset if scan_nonce_offset is None else int(scan_nonce_offset)
        self.cpu_scan_threads = None if cpu_scan_threads is None else int(cpu_scan_threads)

        self.parallel_monero_threads = max(1, int(parallel_monero_threads or self.threads))
        self.parallel_monero_chunk_size = max(1, int(parallel_monero_chunk_size))
        self.parallel_monero_max_results_per_chunk = max(1, int(parallel_monero_max_results_per_chunk))

        scan_mode_count = sum(
            1 for x in (
                self.use_blocknet_p2pool_scan,
                self.use_blocknet_randomx_scan,
                self.use_blocknet_gpu_scan,
                self.use_blocknet_cpu_scan,
                self.use_virtualasic_scan,
                self.use_parallel_monero_scan,
            ) if x
        )
        if scan_mode_count > 1:
            raise RuntimeError(
                "Only one scan mode can be enabled at a time: "
                "use_blocknet_p2pool_scan, use_blocknet_randomx_scan, "
                "use_blocknet_gpu_scan, use_blocknet_cpu_scan, "
                "use_virtualasic_scan, use_parallel_monero_scan"
            )

        self.submit_workers = max(1, int(submit_workers))

        if self.use_blocknet_p2pool_scan and not self.use_blocknet_p2pool:
            raise RuntimeError("use_blocknet_p2pool_scan=True requires use_blocknet_p2pool=True")

        if self.use_virtualasic_scan:
            if not self.virtualasic_kernel:
                self.logger("[Miner] VirtualASIC enabled with empty kernel path; auto-resolution will be attempted.")
            self.logger(
                f"[Miner] VirtualASIC mode: GPU scans on every worker, CPU only verifies candidate nonces "
                f"with one RandomX hash before submit. threads={self.threads}"
            )

        if self.use_parallel_monero_scan:
            self.logger(
                f"[Miner] Parallel Monero scan enabled: miner_workers=1 internal_threads={self.parallel_monero_threads} "
                f"chunk_size={self.parallel_monero_chunk_size} max_results_per_chunk={self.parallel_monero_max_results_per_chunk}"
            )

        if (
            self.use_blocknet_p2pool_scan
            or self.use_blocknet_randomx_scan
            or self.use_blocknet_gpu_scan
            or self.use_blocknet_cpu_scan
            or self.use_virtualasic_scan
            or self.use_parallel_monero_scan
        ):
            self.use_blocknet_randomx = False

        self._bn_cfg: Optional[BlockNetApiCfg] = None
        self._bn_p2pool: Optional[BlockNetP2PoolBackend] = None
        self._bn_rx: Optional[BlockNetRandomXHasher] = None
        self._bn_gpu: Optional[BlockNetGpuScanner] = None
        self._bn_cpu: Optional[BlockNetCpuScanner] = None
        self._rx_batch = max(1, int(randomx_batch_size))

        need_blocknet = (
            self.use_blocknet_p2pool
            or self.use_blocknet_randomx
            or self.use_blocknet_randomx_scan
            or self.use_blocknet_gpu_scan
            or self.use_blocknet_cpu_scan
        )
        if need_blocknet:
            relay = (blocknet_api_relay or "").strip()
            if not relay:
                raise RuntimeError("BlockNet backend enabled but blocknet_api_relay is empty")
            self._bn_cfg = BlockNetApiCfg(
                relay=relay,
                token=(blocknet_api_token or "").strip(),
                prefix=(blocknet_api_prefix or "/v1"),
                verify_tls=bool(blocknet_verify_tls),
            )

        self.job_state = JobState()
        self.share_q: "queue.Queue[Share]" = queue.Queue()
        self._stop = threading.Event()
        self._worker_threads: List[threading.Thread] = []
        self._async_loop: Optional[asyncio.AbstractEventLoop] = None
        self._active_cli: Optional[StratumClient] = None
        self._keepalive_failures = 0

        self._hashes = 0
        self._hash_mu = threading.Lock()
        self._verify_hashes = 0
        self._verify_hash_mu = threading.Lock()

        self.verified_shares = 0
        self.verify_rejected = 0
        self.verify_mismatches = 0
        self.virtualasic_gpu_candidates = 0
        self.accepted = 0
        self.rejected = 0
        self.last_err: str = ""

        self._rx_state_mu = threading.RLock()
        self._rx_state_seed: bytes = b""
        self._rx_state_cache_blob: bytes = b""
        self._rx_state_dataset_blob: bytes = b""

        self._pp_scan: Optional[ParallelMoneroScanner] = None

        if self.use_virtualasic_scan:
            self.logger("[Miner] Using local VirtualASIC scan backend with per-candidate CPU verification...")
            self._bn_gpu = None
            self._bn_cpu = None
            self._bn_rx = None
            self.rx = RandomX(self.logger)

        elif self.use_parallel_monero_scan:
            self.logger("[Miner] Using local Parallel Monero scan backend...")
            self._bn_gpu = None
            self._bn_cpu = None
            self._bn_rx = None
            self.rx = RandomX(self.logger)
            self._pp_scan = ParallelMoneroScanner(
                threads=self.parallel_monero_threads,
                logger=self.logger,
                randomx=self.rx,
                chunk_size=self.parallel_monero_chunk_size,
                max_results_per_chunk=self.parallel_monero_max_results_per_chunk,
            )

        elif self.use_blocknet_gpu_scan:
            assert self._bn_cfg is not None
            self.logger("[Miner] Using BlockNet GPU SCAN API (/gpu/scan)...")
            self._bn_gpu = BlockNetGpuScanner(self._bn_cfg, logger=self.logger)
            self._bn_cpu = None
            self._bn_rx = None
            self.rx = None

        elif self.use_blocknet_cpu_scan:
            assert self._bn_cfg is not None
            self.logger("[Miner] Using BlockNet CPU SCAN API (/cpu/scan)...")
            self._bn_cpu = BlockNetCpuScanner(self._bn_cfg, logger=self.logger)
            self._bn_gpu = None
            self._bn_rx = None
            self.rx = None

        elif self.use_blocknet_randomx or self.use_blocknet_randomx_scan:
            assert self._bn_cfg is not None
            if self.use_blocknet_randomx_scan:
                self.logger("[Miner] Using BlockNet RandomX SCAN API (/randomx/scan)...")
            else:
                self.logger("[Miner] Using BlockNet RandomX API (/randomx/hash_batch)...")
            self._bn_rx = BlockNetRandomXHasher(self._bn_cfg, batch_size=self._rx_batch, logger=self.logger)
            self._bn_gpu = None
            self._bn_cpu = None
            self.rx = None

        else:
            self._bn_gpu = None
            self._bn_cpu = None
            if self.use_blocknet_p2pool_scan:
                self.logger("[Miner] Using BlockNet P2Pool SCAN API (/p2pool/scan)...")
                self.rx = None
            else:
                self.logger("[Miner] Initializing local RandomX...")
                self.rx = RandomX(self.logger)

    def stop(self) -> None:
        if self._stop.is_set():
            return

        self.logger("[Miner] Stop signal received.")
        self._stop.set()
        self.job_state.wake_all()

        if self._pp_scan is not None:
            try:
                self._pp_scan.stop()
            except Exception:
                pass

        loop = self._async_loop
        cli = self._active_cli
        if loop is not None and cli is not None and not loop.is_closed():
            try:
                self.logger("[Miner] Requesting stratum close from stop()...")
                loop.call_soon_threadsafe(asyncio.create_task, cli.close())
            except Exception as e:
                self.logger(f"[Miner] stop() async close scheduling warning: {self._fmt_exc(e)}")

    def add_hashes(self, n: int) -> None:
        with self._hash_mu:
            self._hashes += int(n)

    def pop_hashes(self) -> int:
        with self._hash_mu:
            h = self._hashes
            self._hashes = 0
            return h

    def add_verify_hashes(self, n: int) -> None:
        with self._verify_hash_mu:
            self._verify_hashes += int(n)

    def pop_verify_hashes(self) -> int:
        with self._verify_hash_mu:
            h = self._verify_hashes
            self._verify_hashes = 0
            return h

    def note_verify_result(
        self,
        *,
        passed: int = 0,
        rejected: int = 0,
        mismatched: int = 0,
        gpu_candidates: int = 0,
    ) -> None:
        with self._verify_hash_mu:
            self.verified_shares += int(passed)
            self.verify_rejected += int(rejected)
            self.verify_mismatches += int(mismatched)
            self.virtualasic_gpu_candidates += int(gpu_candidates)

    def get_verify_counters(self) -> Tuple[int, int, int, int]:
        with self._verify_hash_mu:
            return (
                self.verified_shares,
                self.verify_rejected,
                self.verify_mismatches,
                self.virtualasic_gpu_candidates,
            )

    def _create_virtualasic_scanner(self, worker_idx: int) -> VirtualASICScanner:
        self.logger(
            f"[Worker-{worker_idx}] Initializing VirtualASIC engine "
            f"(kernel={self.virtualasic_kernel_name}, core_count={self.virtualasic_core_count})..."
        )
        return VirtualASICScanner(
            dll_path=self.virtualasic_dll,
            kernel_path=self.virtualasic_kernel,
            kernel_name=self.virtualasic_kernel_name,
            core_count=self.virtualasic_core_count,
            logger=self.logger,
            default_max_results=self.scan_max_results,
            enable_randomx_state_args=True,
            strict_randomx_state_args=False,
        )

    def _upload_randomx_state_to_scanner(self, *, scanner: VirtualASICScanner, vm: Any) -> None:
        if not self.rx:
            return

        seed = bytes(getattr(self.rx, "_seed", b"") or b"")
        cache_blob = b""
        dataset_blob = b""
        vm_blob = b""

        with self._rx_state_mu:
            if seed != self._rx_state_seed:
                state = snapshot_randomx_state(
                    self.rx,
                    vm=vm,
                    include_cache=self.virtualasic_stage_randomx_cache,
                    include_dataset=self.virtualasic_stage_randomx_dataset,
                    cache_bytes=self.virtualasic_randomx_cache_bytes,
                    dataset_bytes=self.virtualasic_randomx_dataset_bytes,
                    include_vm_descriptor=False,
                    logger=self.logger,
                )
                self._rx_state_seed = seed
                self._rx_state_cache_blob = bytes(state.get("cache_bytes") or b"")
                self._rx_state_dataset_blob = bytes(state.get("dataset_bytes") or b"")

            cache_blob = self._rx_state_cache_blob
            dataset_blob = self._rx_state_dataset_blob

            if self.virtualasic_stage_randomx_cache and not cache_blob:
                self.virtualasic_stage_randomx_cache = False
                self.logger("[Miner] VirtualASIC cache staging disabled because no safe cache snapshot is available.")

            if self.virtualasic_stage_randomx_dataset and not dataset_blob:
                self.virtualasic_stage_randomx_dataset = False
                self.logger("[Miner] VirtualASIC dataset staging disabled because no safe dataset snapshot is available.")

        if self.virtualasic_stage_vm_descriptor:
            vm_state = snapshot_randomx_state(
                self.rx,
                vm=vm,
                include_cache=False,
                include_dataset=False,
                include_vm_descriptor=True,
                logger=self.logger,
            )
            vm_blob = bytes(vm_state.get("vm_state_bytes") or b"")

        scanner.upload_randomx_state(
            cache_bytes=cache_blob if self.virtualasic_stage_randomx_cache else b"",
            dataset_bytes=dataset_blob if self.virtualasic_stage_randomx_dataset else b"",
            vm_state_bytes=vm_blob if self.virtualasic_stage_vm_descriptor else b"",
        )

    @staticmethod
    def _u64_hex(v: int) -> str:
        return f"0x{int(v) & 0xFFFFFFFFFFFFFFFF:016x}"

    @staticmethod
    def _share_difficulty_from_value(value64: int) -> float:
        v = int(value64) & 0xFFFFFFFFFFFFFFFF
        if v <= 0:
            return float("inf")
        return float((1 << 64) / v)

    @staticmethod
    def _share_quality_ratio(value64: int, target64: int) -> float:
        v = int(value64) & 0xFFFFFFFFFFFFFFFF
        t = int(target64) & 0xFFFFFFFFFFFFFFFF
        if v <= 0:
            return float("inf")
        if t <= 0:
            return 0.0
        return float(t / v)

    def _describe_verified_share(
        self,
        *,
        job: MoneroJob,
        nonce_u32: int,
        verified_hash32: bytes,
        gpu_hash32: bytes,
    ) -> str:
        value64 = int.from_bytes(verified_hash32[24:32], "little", signed=False)
        target64 = int(job.target64)
        quality = self._share_quality_ratio(value64, target64)
        diff_est = self._share_difficulty_from_value(value64)
        mismatch = bool(gpu_hash32 and gpu_hash32 != verified_hash32)
        return (
            f"nonce={nonce_u32} "
            f"value64={self._u64_hex(value64)} "
            f"target64={self._u64_hex(target64)} "
            f"quality_x={quality:.6f} "
            f"share_diff_est={diff_est:,.2f} "
            f"job={job.job_id} "
            f"gpu_cpu_match={'no' if mismatch else 'yes'}"
        )

    def _verify_virtualasic_candidate(
        self,
        *,
        worker_idx: int,
        job: MoneroJob,
        nonce_u32: int,
        vm: Any,
        blob_buf: Any,
        nonce_ptr: Any,
        out_buf: Any,
        rx_hash_into: Callable[[Any, Any, Any], None],
        gpu_hash32: bytes,
    ) -> Optional[Share]:
        nonce_ptr[0] = nonce_u32 & 0xFFFFFFFF
        rx_hash_into(vm, blob_buf, out_buf)
        verified_hash32 = bytes(out_buf)
        self.add_verify_hashes(1)

        mismatch = bool(gpu_hash32 and gpu_hash32 != verified_hash32)
        if mismatch:
            self.note_verify_result(mismatched=1)

        verified_value = int.from_bytes(verified_hash32[24:32], "little", signed=False)
        if verified_value < job.target64:
            self.note_verify_result(passed=1)
            self.logger(
                f"[Worker-{worker_idx}] VASIC verified share queued: "
                f"{self._describe_verified_share(job=job, nonce_u32=nonce_u32, verified_hash32=verified_hash32, gpu_hash32=gpu_hash32)}"
            )
            return Share(job_id=job.job_id, nonce_u32=nonce_u32, result32=verified_hash32)

        self.note_verify_result(rejected=1)
        return None

    def _worker(self, idx: int) -> None:
        self.logger(f"[Worker-{idx}] Started.")

        vm = None
        blob_buf = None
        nonce_ptr = None
        last_seed: Optional[bytes] = None
        out_buf = (c_ubyte * 32)()
        value64 = c_uint64.from_buffer(out_buf, 24)
        nonce_base = 0
        nonce_i = 0
        stride = self.threads
        rx_hash_into = None
        share_put = self.share_q.put
        vasic: Optional[VirtualASICScanner] = None
        last_parallel_diag = 0.0

        local_randomx_mode = (
            not self.use_blocknet_randomx
            and not self.use_blocknet_randomx_scan
            and not self.use_blocknet_p2pool_scan
            and not self.use_blocknet_gpu_scan
            and not self.use_blocknet_cpu_scan
            and not self.use_virtualasic_scan
            and not self.use_parallel_monero_scan
        )
        needs_local_vm = local_randomx_mode or self.use_virtualasic_scan

        try:
            if self.use_virtualasic_scan:
                vasic = self._create_virtualasic_scanner(idx)

            last_seq = 0
            cur_job: Optional[MoneroJob] = None

            while not self._stop.is_set():
                seq, job = self.job_state.wait(last_seq, timeout=0.1)

                if self._stop.is_set():
                    break
                if job is None:
                    continue

                if seq != last_seq:
                    cur_job = job
                    last_seq = seq
                    nonce_base = self.job_state.alloc_nonce_block(1)
                    nonce_i = 0

                    if needs_local_vm:
                        if not self.rx:
                            raise RuntimeError("local RandomX verifier not initialized")

                        rx_hash_into = self.rx.hash_into
                        seed_changed = (last_seed != cur_job.seed_hash)
                        self.rx.ensure_seed(cur_job.seed_hash)

                        if seed_changed or vm is None:
                            if vm is not None:
                                self.rx.destroy_vm(vm)
                            vm = self.rx.create_vm()
                            last_seed = cur_job.seed_hash

                        if blob_buf is None or len(blob_buf) != len(cur_job.blob):
                            blob_buf = (c_ubyte * len(cur_job.blob))()
                        memmove(blob_buf, cur_job.blob, len(cur_job.blob))

                        offset = (
                            self.scan_nonce_offset
                            if (self.use_virtualasic_scan and self.scan_nonce_offset is not None)
                            else cur_job.nonce_offset
                        )
                        nonce_ptr = cast(byref(blob_buf, offset), POINTER(c_uint32))

                        if self.use_virtualasic_scan and vasic is not None:
                            try:
                                self._upload_randomx_state_to_scanner(scanner=vasic, vm=vm)
                            except Exception as e:
                                self.logger(f"[Worker-{idx}] RandomX state staging warning: {self._fmt_exc(e)}")
                    else:
                        rx_hash_into = None
                        if vm is not None and self.rx:
                            self.rx.destroy_vm(vm)
                        vm = None
                        blob_buf = None
                        nonce_ptr = None

                        if self._pp_scan is not None:
                            try:
                                self._pp_scan.reset_stop()
                            except Exception:
                                pass

                if cur_job is None:
                    continue

                if self.use_blocknet_p2pool_scan:
                    try:
                        assert self._bn_p2pool is not None

                        start_nonce = self.job_state.alloc_nonce_block(self.scan_iters)
                        nonce_offset = (
                            self.scan_nonce_offset
                            if self.scan_nonce_offset is not None
                            else (cur_job.nonce_offset if cur_job else 39)
                        )

                        resp = self._bn_p2pool.scan_sync(
                            start_nonce=start_nonce,
                            iters=self.scan_iters,
                            max_results=self.scan_max_results,
                            nonce_offset=nonce_offset,
                            poll_first=self.scan_poll_first,
                        )

                        done = int(resp.get("hashes_done") or 0)
                        if done > 0:
                            self.add_hashes(done)

                        job_id = str(resp.get("job_id") or "")
                        found = resp.get("found") or []
                        if job_id and isinstance(found, list):
                            for one in found:
                                try:
                                    n = int(one.get("nonce_u32"))
                                    hx = str(one.get("hash_hex") or "")
                                    h32 = bytes.fromhex(hx)
                                    if len(h32) == 32:
                                        share_put(Share(job_id=job_id, nonce_u32=n, result32=h32))
                                except Exception:
                                    continue

                        if done <= 0:
                            time.sleep(0.05)

                    except Exception as e:
                        self.last_err = f"p2pool scan failed: {self._fmt_exc(e)}"
                        self.logger(f"[Worker-{idx}] p2pool scan error: {self._fmt_exc(e)}")
                        time.sleep(0.25)

                elif self.use_blocknet_randomx_scan:
                    try:
                        assert self._bn_rx is not None
                        self._bn_rx.set_seed(cur_job.seed_hash)

                        start_nonce = self.job_state.alloc_nonce_block(self.scan_iters)
                        resp = self._bn_rx.scan_sync(
                            blob=cur_job.blob,
                            nonce_offset=cur_job.nonce_offset,
                            start_nonce=start_nonce,
                            iters=self.scan_iters,
                            target64=cur_job.target64,
                            max_results=self.scan_max_results,
                        )

                        done = int(resp.get("hashes_done") or 0)
                        if done > 0:
                            self.add_hashes(done)

                        found = resp.get("found") or []
                        if isinstance(found, list):
                            for one in found:
                                try:
                                    n = int(one.get("nonce_u32"))
                                    hx = str(one.get("hash_hex") or "")
                                    h32 = bytes.fromhex(hx)
                                    if len(h32) == 32:
                                        share_put(Share(job_id=cur_job.job_id, nonce_u32=n, result32=h32))
                                except Exception:
                                    continue

                        if done <= 0:
                            time.sleep(0.05)

                    except Exception as e:
                        self.last_err = f"randomx scan failed: {self._fmt_exc(e)}"
                        self.logger(f"[Worker-{idx}] randomx scan error: {self._fmt_exc(e)}")
                        time.sleep(0.25)


                elif self.use_parallel_monero_scan:
                    try:
                        assert self._pp_scan is not None

                        start_nonce = self.job_state.alloc_nonce_block(self.scan_iters)
                        resp = self._pp_scan.scan_sync(
                            job=cur_job,
                            start_nonce=start_nonce,
                            iters=self.scan_iters,
                            max_results=self.scan_max_results,
                        )
                        done = int(resp.get("hashes_done") or 0)

                        if done > 0:
                            self.add_hashes(done)

                        found = resp.get("found") or []

                        if isinstance(found, list):
                            for one in found:
                                try:
                                    n = int(one.get("nonce_u32"))
                                    hx = str(one.get("hash_hex") or "")
                                    h32 = bytes.fromhex(hx)

                                    if len(h32) == 32:
                                        share_put(Share(job_id=cur_job.job_id, nonce_u32=n, result32=h32))

                                except Exception:
                                    continue

                        if done <= 0:
                            time.sleep(0.002)


                    except Exception as e:

                        self.last_err = f"parallel monero scan failed: {self._fmt_exc(e)}"

                        self.logger(f"[Worker-{idx}] parallel monero scan error: {self._fmt_exc(e)}")

                        time.sleep(0.05)

                elif self.use_virtualasic_scan:
                    try:
                        assert vasic is not None
                        if vm is None or blob_buf is None or nonce_ptr is None or rx_hash_into is None or self.rx is None:
                            raise RuntimeError("VirtualASIC verifier VM is not initialized")

                        start_nonce = self.job_state.alloc_nonce_block(self.scan_iters)
                        nonce_offset = (
                            self.scan_nonce_offset
                            if self.scan_nonce_offset is not None
                            else (cur_job.nonce_offset if cur_job else 39)
                        )

                        resp = vasic.scan_sync(
                            seed_hash=cur_job.seed_hash,
                            blob=cur_job.blob,
                            nonce_offset=nonce_offset,
                            start_nonce=start_nonce,
                            iters=self.scan_iters,
                            target64=cur_job.target64,
                            max_results=self.scan_max_results,
                        )

                        done = int(resp.get("hashes_done") or 0)
                        if done > 0:
                            self.add_hashes(done)

                        found = resp.get("found") or []
                        gpu_candidate_count = 0

                        if isinstance(found, list):
                            for one in found:
                                try:
                                    nonce_u32 = int(one.get("nonce_u32"))
                                except Exception:
                                    continue

                                gpu_candidate_count += 1

                                gpu_hash_hex = str(one.get("hash_hex") or "")
                                try:
                                    gpu_hash32 = bytes.fromhex(gpu_hash_hex) if gpu_hash_hex else b""
                                except Exception:
                                    gpu_hash32 = b""

                                share = self._verify_virtualasic_candidate(
                                    worker_idx=idx,
                                    job=cur_job,
                                    nonce_u32=nonce_u32,
                                    vm=vm,
                                    blob_buf=blob_buf,
                                    nonce_ptr=nonce_ptr,
                                    out_buf=out_buf,
                                    rx_hash_into=rx_hash_into,
                                    gpu_hash32=gpu_hash32,
                                )
                                if share is not None:
                                    share_put(share)

                        if gpu_candidate_count:
                            self.note_verify_result(gpu_candidates=gpu_candidate_count)

                        if done <= 0:
                            time.sleep(0.01)

                    except VirtualASICError as e:
                        self.last_err = f"virtualasic scan failed: {self._fmt_exc(e)}"
                        self.logger(f"[Worker-{idx}] virtualasic scan error: {self._fmt_exc(e)}")
                        time.sleep(0.05)
                    except Exception as e:
                        self.last_err = f"virtualasic scan failed: {self._fmt_exc(e)}"
                        self.logger(f"[Worker-{idx}] virtualasic unexpected error: {self._fmt_exc(e)}")
                        time.sleep(0.05)

                elif self.use_blocknet_gpu_scan:
                    try:
                        assert self._bn_gpu is not None

                        start_nonce = self.job_state.alloc_nonce_block(self.scan_iters)
                        nonce_offset = (
                            self.scan_nonce_offset
                            if self.scan_nonce_offset is not None
                            else (cur_job.nonce_offset if cur_job else 39)
                        )

                        resp = self._bn_gpu.scan_sync(
                            seed_hash=cur_job.seed_hash,
                            blob=cur_job.blob,
                            nonce_offset=nonce_offset,
                            start_nonce=start_nonce,
                            iters=self.scan_iters,
                            target64=cur_job.target64,
                            max_results=self.scan_max_results,
                        )

                        done = int(resp.get("hashes_done") or 0)
                        if done > 0:
                            self.add_hashes(done)

                        found = resp.get("found") or []
                        if isinstance(found, list):
                            for one in found:
                                try:
                                    n = int(one.get("nonce_u32"))
                                    hx = str(one.get("hash_hex") or "")
                                    h32 = bytes.fromhex(hx)
                                    if len(h32) == 32:
                                        share_put(Share(job_id=cur_job.job_id, nonce_u32=n, result32=h32))
                                except Exception:
                                    continue

                        if done <= 0:
                            time.sleep(0.05)

                    except Exception as e:
                        self.last_err = f"gpu scan failed: {self._fmt_exc(e)}"
                        self.logger(f"[Worker-{idx}] gpu scan error: {self._fmt_exc(e)}")
                        time.sleep(0.05)

                elif self.use_blocknet_cpu_scan:
                    try:
                        assert self._bn_cpu is not None

                        start_nonce = self.job_state.alloc_nonce_block(self.scan_iters)
                        nonce_offset = (
                            self.scan_nonce_offset
                            if self.scan_nonce_offset is not None
                            else (cur_job.nonce_offset if cur_job else 39)
                        )

                        resp = self._bn_cpu.scan_sync(
                            seed_hash=cur_job.seed_hash,
                            blob=cur_job.blob,
                            nonce_offset=nonce_offset,
                            start_nonce=start_nonce,
                            iters=self.scan_iters,
                            target64=cur_job.target64,
                            max_results=self.scan_max_results,
                            threads=self.cpu_scan_threads,
                        )

                        done = int(resp.get("hashes_done") or 0)
                        if done > 0:
                            self.add_hashes(done)

                        found = resp.get("found") or []
                        if isinstance(found, list):
                            for one in found:
                                try:
                                    n = int(one.get("nonce_u32"))
                                    hx = str(one.get("hash_hex") or "")
                                    h32 = bytes.fromhex(hx)
                                    if len(h32) == 32:
                                        share_put(Share(job_id=cur_job.job_id, nonce_u32=n, result32=h32))
                                except Exception:
                                    continue

                        if done <= 0:
                            time.sleep(0.05)

                    except Exception as e:
                        self.last_err = f"cpu scan failed: {self._fmt_exc(e)}"
                        self.logger(f"[Worker-{idx}] cpu scan error: {self._fmt_exc(e)}")
                        time.sleep(0.05)

                elif self.use_blocknet_randomx:
                    try:
                        assert self._bn_rx is not None
                        self._bn_rx.set_seed(cur_job.seed_hash)

                        batch_n = self._rx_batch
                        start_nonce = self.job_state.alloc_nonce_block(batch_n)
                        nonces = [(start_nonce + i) & 0xFFFFFFFF for i in range(batch_n)]

                        hashes_opt = self._bn_rx.hash_batch_blob_nonces_sync(
                            blob=cur_job.blob,
                            nonce_offset=cur_job.nonce_offset,
                            nonces_u32=nonces,
                        )

                        valid_hashes = 0
                        for n, h32 in zip(nonces, hashes_opt):
                            if not h32 or len(h32) != 32:
                                continue
                            valid_hashes += 1
                            value = int.from_bytes(h32[24:32], "little", signed=False)
                            if value < cur_job.target64:
                                share_put(Share(job_id=cur_job.job_id, nonce_u32=n, result32=h32))

                        if valid_hashes:
                            self.add_hashes(valid_hashes)
                        else:
                            time.sleep(0.05)

                    except Exception as e:
                        self.last_err = f"remote hash failed: {self._fmt_exc(e)}"
                        self.logger(f"[Worker-{idx}] remote hash error: {self._fmt_exc(e)}")
                        time.sleep(0.25)

                else:
                    if vm is None or blob_buf is None or nonce_ptr is None or self.rx is None or rx_hash_into is None:
                        continue

                    batch_size = 1024
                    done = 0
                    target = cur_job.target64
                    job_id = cur_job.job_id

                    for i in range(batch_size):
                        if (i & 15) == 0 and (self._stop.is_set() or self.job_state.seq != last_seq):
                            break

                        nonce = (nonce_base + (nonce_i + i) * stride) & 0xFFFFFFFF
                        nonce_ptr[0] = nonce
                        rx_hash_into(vm, blob_buf, out_buf)

                        if value64.value < target:
                            share_put(Share(job_id=job_id, nonce_u32=nonce, result32=bytes(out_buf)))
                        done += 1

                    nonce_i += done
                    if done:
                        self.add_hashes(done)

        except Exception as e:
            self.last_err = f"Worker {idx} crashed: {self._fmt_exc(e)}"
            self.logger(f"[Worker-{idx}] FATAL ERROR: {self._fmt_exc(e)}")
            traceback.print_exc()
        finally:
            try:
                if self._pp_scan is not None:
                    try:
                        self._pp_scan.stop()
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                if vm and self.rx:
                    self.rx.destroy_vm(vm)
            except Exception:
                pass

            try:
                if vasic is not None:
                    vasic.close()
            except Exception:
                pass

            self.logger(f"[Worker-{idx}] Stopped.")

    async def run(self, *, on_stats: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        cli: Optional[StratumClient] = None
        self._async_loop = asyncio.get_running_loop()
        self._active_cli = None

        if self.use_blocknet_p2pool:
            assert self._bn_cfg is not None
            self._bn_p2pool = BlockNetP2PoolBackend(self._bn_cfg, logger=self.logger)
        else:
            cli = StratumClient(self.stratum_host, self.stratum_port, logger=self.logger)
            self._active_cli = cli

        try:
            if self.use_blocknet_p2pool:
                assert self._bn_p2pool is not None
                self.logger("[Miner] Opening BlockNet P2Pool session...")
                first_job = await self._bn_p2pool.open()

                if first_job:
                    self.job_state.set(MoneroJob.from_stratum(first_job))
                else:
                    self.logger("[Miner] No initial job from /p2pool/open; polling for job...")
                    j = await self._bn_p2pool.get_job(max_msgs=32)
                    self.job_state.set(MoneroJob.from_stratum(j))
            else:
                assert cli is not None
                self.logger(f"[Miner] Connecting to {self.stratum_host}:{self.stratum_port}...")
                await cli.connect()
                self.logger("[Miner] Connected. Logging in...")

                login = await cli.login(wallet=self.wallet, password=self.password, agent=self.agent)
                self.logger(f"[Miner] Logged in. Client ID: {login.client_id}")

                self.job_state.set(MoneroJob.from_stratum(login.job))

            self._worker_threads = []
            worker_count = 1 if self.use_parallel_monero_scan else self.threads

            for i in range(worker_count):
                t = threading.Thread(target=self._worker, args=(i,), name=f"Worker-{i}", daemon=True)
                self._worker_threads.append(t)
                t.start()

            async def job_loop() -> None:
                last_job_id = ""
                last_key = None

                while not self._stop.is_set():
                    if self.use_blocknet_p2pool:
                        assert self._bn_p2pool is not None
                        try:
                            poll = await self._bn_p2pool.poll(max_msgs=32)
                            job = poll.get("job") or {}
                            updated = bool(poll.get("job_updated"))

                            if job:
                                jid = str(job.get("job_id", "") or "")
                                if updated or (jid and jid != last_job_id):
                                    last_job_id = jid
                                    self.job_state.set(MoneroJob.from_stratum(job))
                        except Exception as e:
                            self.last_err = f"p2pool poll error: {self._fmt_exc(e)}"
                            self.logger(f"[Miner] p2pool poll error: {self._fmt_exc(e)}")
                            await asyncio.sleep(0.05)

                        await asyncio.sleep(0.05)
                    else:
                        assert cli is not None
                        try:
                            j = await cli.next_job()
                        except (asyncio.CancelledError, StratumDisconnected):
                            if self._stop.is_set():
                                return
                            raise

                        mj = MoneroJob.from_stratum(j)
                        key = (mj.seed_hash, mj.target64, mj.blob)
                        if key != last_key:
                            last_key = key
                            self.job_state.set(mj)

            async def submit_loop(worker_idx: int) -> None:
                while not self._stop.is_set():
                    try:
                        share = await asyncio.to_thread(self.share_q.get, True, 0.1)
                        try:
                            if self.use_blocknet_p2pool:
                                assert self._bn_p2pool is not None
                                await self._bn_p2pool.submit(
                                    job_id=share.job_id,
                                    nonce_hex=share.nonce_hex,
                                    result_hex=share.result_hex,
                                )
                            else:
                                assert cli is not None
                                await cli.submit(
                                    job_id=share.job_id,
                                    nonce_hex=share.nonce_hex,
                                    result_hex=share.result_hex,
                                )

                            self.accepted += 1
                            value64 = int.from_bytes(share.result32[24:32], "little", signed=False) if len(share.result32) >= 32 else 0
                            diff_est = self._share_difficulty_from_value(value64) if value64 else 0.0
                            self.logger(
                                f"[Submit-{worker_idx}] Share accepted! "
                                f"nonce={share.nonce_u32} value64={self._u64_hex(value64)} "
                                f"share_diff_est={diff_est:,.2f} job={share.job_id}"
                            )
                        except Exception as e:
                            self.rejected += 1
                            value64 = int.from_bytes(share.result32[24:32], "little", signed=False) if len(share.result32) >= 32 else 0
                            diff_est = self._share_difficulty_from_value(value64) if value64 else 0.0
                            self.logger(
                                f"[Submit-{worker_idx}] Share rejected: {self._fmt_exc(e)} "
                                f"nonce={share.nonce_u32} value64={self._u64_hex(value64)} "
                                f"share_diff_est={diff_est:,.2f} job={share.job_id}"
                            )
                    except queue.Empty:
                        continue

            async def stats_loop() -> None:
                last_t = time.time()

                while not self._stop.is_set():
                    for _ in range(20):
                        if self._stop.is_set():
                            return
                        await asyncio.sleep(0.1)

                    now = time.time()
                    dt = max(1e-9, now - last_t)
                    hps = self.pop_hashes() / dt
                    verify_hps = self.pop_verify_hashes() / dt if self.use_virtualasic_scan else None
                    last_t = now

                    current_job = self.job_state.get()
                    job_id_str = current_job.job_id if current_job else ""
                    verify_passed, verify_failed, verify_mismatches, vasic_gpu_candidates = self.get_verify_counters()

                    if self.use_virtualasic_scan:
                        backend_rx = "virtualasic_gpu_scan_cpu_verify_submit"
                    elif self.use_parallel_monero_scan:
                        backend_rx = "parallel_monero_scan"
                    elif self.use_blocknet_p2pool_scan:
                        backend_rx = "blocknet_p2pool_scan"
                    elif self.use_blocknet_gpu_scan:
                        backend_rx = "blocknet_gpu_scan"
                    elif self.use_blocknet_cpu_scan:
                        backend_rx = "blocknet_cpu_scan"
                    elif self.use_blocknet_randomx_scan:
                        backend_rx = "blocknet_randomx_scan"
                    elif self.use_blocknet_randomx:
                        backend_rx = "blocknet_hash_batch"
                    else:
                        backend_rx = "local"

                    if on_stats:
                        on_stats({
                            "hashrate_hs": hps,
                            "verify_hashrate_hs": verify_hps,
                            "threads": (self.parallel_monero_threads if self.use_parallel_monero_scan else self.threads),
                            "miner_worker_threads": len(self._worker_threads),
                            "accepted": self.accepted,
                            "rejected": self.rejected,
                            "last_error": self.last_err,
                            "height": (current_job.height if current_job else None),
                            "job_id": job_id_str,
                            "backend_p2pool": ("blocknet" if self.use_blocknet_p2pool else "stratum"),
                            "backend_randomx": backend_rx,
                            "backend_parallel_monero_scan": self.use_parallel_monero_scan,
                            "parallel_monero_enabled": self.use_parallel_monero_scan,
                            "parallel_monero_threads": (self.parallel_monero_threads if self.use_parallel_monero_scan else None),
                            "parallel_monero_chunk_size": (self.parallel_monero_chunk_size if self.use_parallel_monero_scan else None),
                            "parallel_monero_max_results_per_chunk": (
                                self.parallel_monero_max_results_per_chunk if self.use_parallel_monero_scan else None
                            ),
                            "submit_workers": self.submit_workers,
                            "scan_iters": (
                                self.scan_iters if (
                                    self.use_virtualasic_scan
                                    or self.use_parallel_monero_scan
                                    or self.use_blocknet_p2pool_scan
                                    or self.use_blocknet_randomx_scan
                                    or self.use_blocknet_gpu_scan
                                    or self.use_blocknet_cpu_scan
                                ) else None
                            ),
                            "verified_shares": (verify_passed if self.use_virtualasic_scan else None),
                            "verify_rejected": (verify_failed if self.use_virtualasic_scan else None),
                            "verify_mismatches": (verify_mismatches if self.use_virtualasic_scan else None),
                            "virtualasic_gpu_candidates": (vasic_gpu_candidates if self.use_virtualasic_scan else None),
                            "virtualasic_stage_randomx_cache": (
                                self.virtualasic_stage_randomx_cache if self.use_virtualasic_scan else None
                            ),
                            "virtualasic_stage_randomx_dataset": (
                                self.virtualasic_stage_randomx_dataset if self.use_virtualasic_scan else None
                            ),
                            "virtualasic_stage_vm_descriptor": (
                                self.virtualasic_stage_vm_descriptor if self.use_virtualasic_scan else None
                            ),
                        })

            async def keepalive_loop() -> None:
                if self.use_blocknet_p2pool:
                    while not self._stop.is_set():
                        for _ in range(300):
                            if self._stop.is_set():
                                return
                            await asyncio.sleep(0.1)
                else:
                    assert cli is not None
                    while not self._stop.is_set():
                        for _ in range(300):
                            if self._stop.is_set():
                                return
                            await asyncio.sleep(0.1)

                        if self._stop.is_set():
                            return

                        try:
                            await cli.keepalived()
                            self._keepalive_failures = 0
                            if self.last_err.startswith("keepalive error:"):
                                self.last_err = ""
                        except (asyncio.CancelledError, StratumDisconnected) as e:
                            if self._stop.is_set():
                                return
                            self._keepalive_failures += 1
                            if self._keepalive_failures in (1, 5) or (self._keepalive_failures % 10 == 0):
                                self.logger(
                                    f"[Miner] keepalive interrupted ({self._keepalive_failures}); "
                                    f"waiting for reconnect... detail={self._fmt_exc(e)}"
                                )
                            await asyncio.sleep(0.2)
                            continue
                        except Exception as e:
                            self._keepalive_failures += 1
                            detail = self._fmt_exc(e)
                            self.last_err = f"keepalive error: {detail}"
                            self.logger(f"[Miner] keepalive error: {detail}")
                            await asyncio.sleep(0.5)

            tasks = [
                asyncio.create_task(job_loop()),
                asyncio.create_task(stats_loop()),
                asyncio.create_task(keepalive_loop()),
            ]

            for i in range(self.submit_workers):
                tasks.append(asyncio.create_task(submit_loop(i)))

            while not self._stop.is_set():
                await asyncio.sleep(0.1)

            self.logger("[Miner] Shutting down tasks...")
            for t in tasks:
                t.cancel()

            try:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=3.0)
            except Exception:
                pass

        finally:
            self.logger("[Miner] Closing connection/session...")
            try:
                if self.use_blocknet_p2pool and self._bn_p2pool:
                    await self._bn_p2pool.close()
                elif cli:
                    await cli.close()
            except Exception:
                pass

            self._stop.set()
            self.job_state.wake_all()

            if self._pp_scan is not None:
                try:
                    self._pp_scan.stop()
                except Exception:
                    pass

            for t in self._worker_threads:
                try:
                    t.join(timeout=2.0)
                except Exception:
                    pass

            if self._pp_scan is not None:
                try:
                    self._pp_scan.close()
                except Exception:
                    pass
                self._pp_scan = None

            self._active_cli = None
            self._async_loop = None
            self.logger("[Miner] Shutdown complete.")

    @staticmethod
    def _fmt_exc(exc: BaseException) -> str:
        text = str(exc).strip()
        return text or exc.__class__.__name__