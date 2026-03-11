from __future__ import annotations

import asyncio
import queue
import secrets
import threading
import time
import traceback
from ctypes import POINTER, byref, c_uint32, c_uint64, c_ubyte, cast, memmove
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from monero_job import MoneroJob
from randomx_ctypes import RandomX
from stratum_client import StratumClient

from blocknet_mining_backend import (
    BlockNetApiCfg,
    BlockNetGpuScanner,
    BlockNetP2PoolBackend,
    BlockNetRandomXHasher,
)


@dataclass
class Share:
    job_id: str
    nonce_u32: int
    result32: bytes
    job_seq: int = 0
    found_at: float = 0.0

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
        with self._mu:
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

        # BlockNet mining backends (optional)
        use_blocknet_p2pool: bool = False,
        use_blocknet_randomx: bool = False,

        # server-side scanning modes
        use_blocknet_p2pool_scan: bool = False,
        use_blocknet_randomx_scan: bool = False,
        use_blocknet_gpu_scan: bool = False,

        # BlockNet API config
        blocknet_api_relay: str = "",
        blocknet_api_token: str = "",
        blocknet_api_prefix: str = "/v1",
        blocknet_verify_tls: bool = False,

        # RandomX batch hashing config
        randomx_batch_size: int = 64,

        # share submit workers
        submit_workers: int = 1,

        # scan tuning
        scan_iters: int = 1000,
        scan_max_results: int = 4,
        scan_poll_first: bool = False,
        scan_nonce_offset: Optional[int] = None,

        # submit recovery tuning
        max_submit_age_s: float = 10.0,
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

        self.scan_iters = max(1, int(scan_iters))
        self.scan_max_results = max(1, int(scan_max_results))
        self.scan_poll_first = bool(scan_poll_first)
        self.scan_nonce_offset = scan_nonce_offset if scan_nonce_offset is None else int(scan_nonce_offset)
        self.max_submit_age_s = max(1.0, float(max_submit_age_s))

        scan_mode_count = sum(
            1 for x in (
                self.use_blocknet_p2pool_scan,
                self.use_blocknet_randomx_scan,
                self.use_blocknet_gpu_scan,
            ) if x
        )
        if scan_mode_count > 1:
            raise RuntimeError(
                "Only one scan mode can be enabled at a time: "
                "use_blocknet_p2pool_scan, use_blocknet_randomx_scan, use_blocknet_gpu_scan"
            )

        self.submit_workers = max(1, int(submit_workers))

        if self.use_blocknet_p2pool_scan and not self.use_blocknet_p2pool:
            raise RuntimeError("use_blocknet_p2pool_scan=True requires use_blocknet_p2pool=True")

        if self.use_blocknet_p2pool and self.submit_workers != 1:
            self.logger("[Miner] Forcing submit_workers=1 for BlockNet P2Pool session safety.")
            self.submit_workers = 1

        if self.use_blocknet_p2pool_scan or self.use_blocknet_randomx_scan or self.use_blocknet_gpu_scan:
            self.use_blocknet_randomx = False

        self._bn_cfg: Optional[BlockNetApiCfg] = None
        self._bn_p2pool: Optional[BlockNetP2PoolBackend] = None
        self._bn_rx: Optional[BlockNetRandomXHasher] = None
        self._bn_gpu: Optional[BlockNetGpuScanner] = None
        self._rx_batch = max(1, int(randomx_batch_size))

        need_blocknet = (
            self.use_blocknet_p2pool
            or self.use_blocknet_randomx
            or self.use_blocknet_randomx_scan
            or self.use_blocknet_gpu_scan
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

        self._hashes = 0
        self._hash_mu = threading.Lock()

        self.accepted = 0
        self.rejected = 0
        self.duplicates = 0
        self.transport_failures = 0
        self.recovered = 0
        self.stale_dropped = 0
        self.last_err: str = ""

        self._bn_p2pool_lock: Optional[asyncio.Lock] = None
        self._session_reset_lock: Optional[asyncio.Lock] = None

        self._resetting_flag = threading.Event()
        self._scan_http_sem = threading.Semaphore(1)
        self._last_reset_attempt = 0.0
        self._reset_backoff_s = 1.0

        if self.use_blocknet_gpu_scan:
            assert self._bn_cfg is not None
            self.logger("[Miner] Using BlockNet GPU SCAN API (/gpu/scan)...")
            self._bn_gpu = BlockNetGpuScanner(self._bn_cfg, logger=self.logger)
            self._bn_rx = None
            self.rx: Optional[RandomX] = None

        elif self.use_blocknet_randomx or self.use_blocknet_randomx_scan:
            assert self._bn_cfg is not None
            if self.use_blocknet_randomx_scan:
                self.logger("[Miner] Using BlockNet RandomX SCAN API (/randomx/scan)...")
            else:
                self.logger("[Miner] Using BlockNet RandomX API (/randomx/hash_batch)...")
            self._bn_rx = BlockNetRandomXHasher(self._bn_cfg, batch_size=self._rx_batch, logger=self.logger)
            self._bn_gpu = None
            self.rx = None

        else:
            self._bn_gpu = None
            if self.use_blocknet_p2pool_scan:
                self.logger("[Miner] Using BlockNet P2Pool SCAN API (/p2pool/scan)...")
                self.rx = None
            else:
                self.logger("[Miner] Initializing local RandomX...")
                self.rx = RandomX(self.logger)

    def stop(self) -> None:
        self.logger("[Miner] Stop signal received.")
        self._stop.set()

    def add_hashes(self, n: int) -> None:
        with self._hash_mu:
            self._hashes += int(n)

    def pop_hashes(self) -> int:
        with self._hash_mu:
            h = self._hashes
            self._hashes = 0
            return h

    async def _bn_call(self, fn, *args, **kwargs):
        assert self._bn_p2pool is not None
        assert self._bn_p2pool_lock is not None
        async with self._bn_p2pool_lock:
            return await fn(*args, **kwargs)

    def _p2pool_session_open(self) -> bool:
        return bool(self._bn_p2pool is not None and self._bn_p2pool.is_open)

    def _classify_submit_error(self, exc: Exception) -> str:
        s = str(exc).lower()

        if "duplicate_submit" in s or "duplicate" in s:
            return "duplicate"

        if "stale_job" in s or "stale" in s or "low diff" in s:
            return "stale"

        if (
            "unknown_session" in s
            or "session_not_ready" in s
            or "session socket invalid" in s
            or "session not open" in s
            or "p2pool session not open" in s
            or "login_failed" in s
            or "stratum login failed" in s
        ):
            return "session"

        if (
            "submit_transport_lost" in s
            or "recv failed" in s
            or "send failed" in s
            or "timeout" in s
            or "timed out" in s
            or ("submit_failed" in s and "502" in s)
            or "http error 502" in s
            or "connect failed" in s
        ):
            return "transport"

        return "other"

    def _share_is_stale_local(self, share: Share) -> bool:
        cur = self.job_state.get()
        if cur is None:
            return True
        if cur.job_id != share.job_id:
            return True
        if share.found_at and (time.monotonic() - share.found_at) > self.max_submit_age_s:
            return True
        return False

    async def _ensure_blocknet_session(self, reason: str) -> bool:
        if not self.use_blocknet_p2pool or not self._bn_p2pool:
            return False

        if self._bn_p2pool.is_open:
            return True

        assert self._session_reset_lock is not None

        if self._session_reset_lock.locked():
            for _ in range(40):
                if self._stop.is_set():
                    return False
                await asyncio.sleep(0.05)
                if self._bn_p2pool.is_open:
                    return True
            return self._bn_p2pool.is_open

        return await self._reset_blocknet_session(reason)

    async def _reset_blocknet_session(self, reason: str) -> bool:
        if not self.use_blocknet_p2pool or not self._bn_p2pool:
            return False

        assert self._session_reset_lock is not None

        async with self._session_reset_lock:
            if self._stop.is_set():
                return False

            now = time.monotonic()
            dt = now - self._last_reset_attempt
            if dt < self._reset_backoff_s:
                await asyncio.sleep(self._reset_backoff_s - dt)
            self._last_reset_attempt = time.monotonic()

            self._resetting_flag.set()
            self.logger(f"[Miner] Resetting BlockNet P2Pool session: {reason}")

            try:
                self._bn_p2pool.invalidate_local()
                await asyncio.sleep(0.20)

                first_job = await self._bn_call(self._bn_p2pool.open)

                if first_job:
                    self.job_state.set(MoneroJob.from_stratum(first_job))
                else:
                    j = await self._bn_call(self._bn_p2pool.get_job, max_msgs=32)
                    if j:
                        self.job_state.set(MoneroJob.from_stratum(j))

                self.logger("[Miner] BlockNet P2Pool session reopened.")
                return True

            except Exception as e:
                self.last_err = f"session reset failed: {e}"
                self.logger(f"[Miner] session reset failed: {e}")
                try:
                    self._bn_p2pool.invalidate_local()
                except Exception:
                    pass
                return False

            finally:
                self._resetting_flag.clear()

    async def _submit_share_blocknet(self, share: Share) -> str:
        """
        Returns one of:
          accepted
          duplicate
          stale
          rejected
          transport_failed
        """
        assert self._bn_p2pool is not None

        if self._share_is_stale_local(share):
            return "stale"

        if not self._bn_p2pool.is_open:
            ok = await self._ensure_blocknet_session("submit saw closed session")
            if not ok:
                return "transport_failed"
            if self._share_is_stale_local(share):
                return "stale"

        try:
            await self._bn_call(
                self._bn_p2pool.submit,
                job_id=share.job_id,
                nonce_hex=share.nonce_hex,
                result_hex=share.result_hex,
            )
            return "accepted"

        except Exception as e:
            kind = self._classify_submit_error(e)

            if kind == "duplicate":
                return "duplicate"

            if kind == "stale":
                return "stale"

            if kind in ("transport", "session"):
                self.transport_failures += 1
                self.logger(f"[Submit] transport/session failure for nonce {share.nonce_hex}: {e}")

                ok = await self._ensure_blocknet_session(str(e))
                if not ok:
                    return "transport_failed"

                if self._share_is_stale_local(share):
                    return "stale"

                try:
                    await self._bn_call(
                        self._bn_p2pool.submit,
                        job_id=share.job_id,
                        nonce_hex=share.nonce_hex,
                        result_hex=share.result_hex,
                    )
                    self.recovered += 1
                    return "accepted"

                except Exception as e2:
                    kind2 = self._classify_submit_error(e2)

                    if kind2 == "duplicate":
                        self.recovered += 1
                        return "duplicate"

                    if kind2 == "stale":
                        return "stale"

                    self.last_err = f"submit retry failed: {e2}"
                    self.logger(f"[Submit] retry failed for nonce {share.nonce_hex}: {e2}")
                    return "transport_failed"

            self.last_err = f"submit failed: {e}"
            self.logger(f"[Submit] unrecovered reject for nonce {share.nonce_hex}: {e}")
            return "rejected"

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

        try:
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

                    if (
                        not self.use_blocknet_randomx
                        and not self.use_blocknet_randomx_scan
                        and not self.use_blocknet_p2pool_scan
                        and not self.use_blocknet_gpu_scan
                    ):
                        if not self.rx:
                            raise RuntimeError("local RandomX not initialized")

                        rx_hash_into = self.rx.hash_into
                        seed_changed = last_seed != cur_job.seed_hash
                        self.rx.ensure_seed(cur_job.seed_hash)

                        if seed_changed or vm is None:
                            if vm is not None:
                                self.rx.destroy_vm(vm)
                            vm = self.rx.create_vm()
                            last_seed = cur_job.seed_hash

                        if blob_buf is None or len(blob_buf) != len(cur_job.blob):
                            blob_buf = (c_ubyte * len(cur_job.blob))()
                        memmove(blob_buf, cur_job.blob, len(cur_job.blob))

                        offset = cur_job.nonce_offset
                        nonce_ptr = cast(byref(blob_buf, offset), POINTER(c_uint32))
                    else:
                        rx_hash_into = None
                        if vm is not None and self.rx:
                            self.rx.destroy_vm(vm)
                        vm = None
                        blob_buf = None
                        nonce_ptr = None

                if cur_job is None:
                    continue

                if self.use_blocknet_p2pool_scan:
                    try:
                        assert self._bn_p2pool is not None

                        if self._resetting_flag.is_set() or not self._bn_p2pool.is_open:
                            time.sleep(0.05)
                            continue

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
                            now_found = time.monotonic()
                            for one in found:
                                try:
                                    n = int(one.get("nonce_u32"))
                                    hx = str(one.get("hash_hex") or "")
                                    h32 = bytes.fromhex(hx)
                                    if len(h32) == 32:
                                        self.logger(f"[Worker-{idx}] SHARE FOUND! Nonce: {n}")
                                        share_put(
                                            Share(
                                                job_id=job_id,
                                                nonce_u32=n,
                                                result32=h32,
                                                job_seq=last_seq,
                                                found_at=now_found,
                                            )
                                        )
                                except Exception:
                                    continue

                        if done <= 0:
                            time.sleep(0.05)

                    except Exception as e:
                        self.last_err = f"p2pool scan failed: {e}"
                        self.logger(f"[Worker-{idx}] p2pool scan error: {e}")
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
                            now_found = time.monotonic()
                            for one in found:
                                try:
                                    n = int(one.get("nonce_u32"))
                                    hx = str(one.get("hash_hex") or "")
                                    h32 = bytes.fromhex(hx)
                                    if len(h32) == 32:
                                        share_put(
                                            Share(
                                                job_id=cur_job.job_id,
                                                nonce_u32=n,
                                                result32=h32,
                                                job_seq=last_seq,
                                                found_at=now_found,
                                            )
                                        )
                                except Exception:
                                    continue

                        if done <= 0:
                            time.sleep(0.05)

                    except Exception as e:
                        self.last_err = f"randomx scan failed: {e}"
                        self.logger(f"[Worker-{idx}] randomx scan error: {e}")
                        time.sleep(0.25)

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
                        now_found = time.monotonic()

                        for n, h32 in zip(nonces, hashes_opt):
                            if not h32 or len(h32) != 32:
                                continue

                            valid_hashes += 1
                            value = int.from_bytes(h32[24:32], "little", signed=False)
                            if value < cur_job.target64:
                                self.logger(f"[Worker-{idx}] SHARE FOUND! Nonce: {n}")
                                share_put(
                                    Share(
                                        job_id=cur_job.job_id,
                                        nonce_u32=n,
                                        result32=h32,
                                        job_seq=last_seq,
                                        found_at=now_found,
                                    )
                                )

                        if valid_hashes:
                            self.add_hashes(valid_hashes)
                        else:
                            time.sleep(0.05)

                    except Exception as e:
                        self.last_err = f"remote hash failed: {e}"
                        self.logger(f"[Worker-{idx}] remote hash error: {e}")
                        time.sleep(0.25)

                elif self.use_blocknet_gpu_scan:
                    try:
                        assert self._bn_gpu is not None

                        if self.use_blocknet_p2pool and self._bn_p2pool is not None:
                            if self._resetting_flag.is_set() or not self._bn_p2pool.is_open:
                                time.sleep(0.05)
                                continue

                        start_nonce = self.job_state.alloc_nonce_block(self.scan_iters)
                        nonce_offset = (
                            self.scan_nonce_offset
                            if self.scan_nonce_offset is not None
                            else (cur_job.nonce_offset if cur_job else 39)
                        )

                        with self._scan_http_sem:
                            if self.use_blocknet_p2pool and self._bn_p2pool is not None:
                                if self._resetting_flag.is_set() or not self._bn_p2pool.is_open:
                                    time.sleep(0.05)
                                    continue

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
                            now_found = time.monotonic()
                            for one in found:
                                try:
                                    n = int(one.get("nonce_u32"))
                                    hx = str(one.get("hash_hex") or "")
                                    h32 = bytes.fromhex(hx)
                                    if len(h32) == 32:
                                        self.logger(f"[Worker-{idx}] GPU SHARE FOUND! Nonce: {n}")
                                        share_put(
                                            Share(
                                                job_id=cur_job.job_id,
                                                nonce_u32=n,
                                                result32=h32,
                                                job_seq=last_seq,
                                                found_at=now_found,
                                            )
                                        )
                                except Exception:
                                    continue

                        if done <= 0:
                            time.sleep(0.02)

                    except Exception as e:
                        self.last_err = f"gpu scan failed: {e}"
                        self.logger(f"[Worker-{idx}] gpu scan error: {e}")
                        time.sleep(0.05)

                else:
                    if vm is None or blob_buf is None or nonce_ptr is None or self.rx is None:
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
                            self.logger(f"[Worker-{idx}] SHARE FOUND! Nonce: {nonce}")
                            share_put(
                                Share(
                                    job_id=job_id,
                                    nonce_u32=nonce,
                                    result32=bytes(out_buf),
                                    job_seq=last_seq,
                                    found_at=time.monotonic(),
                                )
                            )
                        done += 1

                    nonce_i += done
                    if done:
                        self.add_hashes(done)

        except Exception as e:
            self.last_err = f"Worker {idx} crashed: {e}"
            self.logger(f"[Worker-{idx}] FATAL ERROR: {e}")
            traceback.print_exc()
        finally:
            try:
                if vm and self.rx:
                    self.rx.destroy_vm(vm)
            except Exception:
                pass
            self.logger(f"[Worker-{idx}] Stopped.")

    async def run(self, *, on_stats: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        cli: Optional[StratumClient] = None

        if self.use_blocknet_p2pool:
            assert self._bn_cfg is not None
            self._bn_p2pool = BlockNetP2PoolBackend(self._bn_cfg, logger=self.logger)
        else:
            cli = StratumClient(self.stratum_host, self.stratum_port, logger=self.logger)

        self._bn_p2pool_lock = asyncio.Lock()
        self._session_reset_lock = asyncio.Lock()

        try:
            if self.use_blocknet_p2pool:
                assert self._bn_p2pool is not None
                self.logger("[Miner] Opening BlockNet P2Pool session...")
                first_job = await self._bn_call(self._bn_p2pool.open)

                if first_job:
                    self.job_state.set(MoneroJob.from_stratum(first_job))
                else:
                    self.logger("[Miner] No initial job from /p2pool/open; polling for job...")
                    j = await self._bn_call(self._bn_p2pool.get_job, max_msgs=32)
                    self.job_state.set(MoneroJob.from_stratum(j))
            else:
                assert cli is not None
                self.logger(f"[Miner] Connecting to {self.stratum_host}:{self.stratum_port}...")
                await cli.connect()
                self.logger("[Miner] Connected. Logging in...")

                login = await cli.login(wallet=self.wallet, password=self.password, agent=self.agent)
                self.logger(f"[Miner] Logged in. Client ID: {login.client_id}")

                self.job_state.set(MoneroJob.from_stratum(login.job))

            for i in range(self.threads):
                t = threading.Thread(target=self._worker, args=(i,), name=f"Worker-{i}", daemon=True)
                t.start()

            async def job_loop() -> None:
                last_job_id = ""
                last_key = None

                while not self._stop.is_set():
                    if self.use_blocknet_p2pool:
                        assert self._bn_p2pool is not None

                        if self._resetting_flag.is_set():
                            await asyncio.sleep(0.10)
                            continue

                        if not self._bn_p2pool.is_open:
                            ok = await self._ensure_blocknet_session("job loop detected closed session")
                            if not ok:
                                await asyncio.sleep(0.25)
                                continue

                        try:
                            poll = await self._bn_call(self._bn_p2pool.poll, max_msgs=32)
                            job = poll.get("job") or {}
                            updated = bool(poll.get("job_updated"))

                            if job:
                                jid = str(job.get("job_id", "") or "")
                                if updated or (jid and jid != last_job_id):
                                    last_job_id = jid
                                    self.job_state.set(MoneroJob.from_stratum(job))

                        except Exception as e:
                            self.last_err = f"p2pool poll error: {e}"
                            self.logger(f"[Miner] p2pool poll error: {e}")

                            kind = self._classify_submit_error(e)
                            if kind in ("transport", "session"):
                                await self._ensure_blocknet_session(f"poll failed: {e}")
                                await asyncio.sleep(0.10)
                            else:
                                await asyncio.sleep(0.10)

                        await asyncio.sleep(0.05)
                    else:
                        assert cli is not None
                        j = await cli.next_job()
                        mj = MoneroJob.from_stratum(j)
                        key = (mj.seed_hash, mj.target64, mj.blob)
                        if key != last_key:
                            last_key = key
                            self.job_state.set(mj)

            async def submit_loop(worker_idx: int) -> None:
                while not self._stop.is_set():
                    try:
                        share = await asyncio.to_thread(self.share_q.get, True, 0.5)
                    except queue.Empty:
                        continue

                    try:
                        if self.use_blocknet_p2pool:
                            result = await self._submit_share_blocknet(share)

                            if result == "accepted":
                                self.accepted += 1
                                self.logger(f"[Submit-{worker_idx}] Share accepted!")

                            elif result == "duplicate":
                                self.duplicates += 1
                                self.logger(f"[Submit-{worker_idx}] Share duplicate (likely already accepted).")

                            elif result == "stale":
                                self.stale_dropped += 1
                                self.logger(f"[Submit-{worker_idx}] Share stale; dropped.")

                            elif result == "transport_failed":
                                self.rejected += 1
                                self.logger(f"[Submit-{worker_idx}] Share lost after transport/session recovery attempt.")

                            else:
                                self.rejected += 1
                                self.logger(f"[Submit-{worker_idx}] Share rejected.")
                        else:
                            assert cli is not None
                            await cli.submit(
                                job_id=share.job_id,
                                nonce_hex=share.nonce_hex,
                                result_hex=share.result_hex,
                            )
                            self.accepted += 1
                            self.logger(f"[Submit-{worker_idx}] Share accepted!")

                    except Exception as e:
                        self.rejected += 1
                        self.last_err = f"submit loop failed: {e}"
                        self.logger(f"[Submit-{worker_idx}] Share rejected: {e}")

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
                    last_t = now

                    current_job = self.job_state.get()
                    job_id_str = current_job.job_id if current_job else ""

                    if self.use_blocknet_p2pool_scan:
                        backend_rx = "blocknet_p2pool_scan"
                    elif self.use_blocknet_gpu_scan:
                        backend_rx = "blocknet_gpu_scan"
                    elif self.use_blocknet_randomx_scan:
                        backend_rx = "blocknet_randomx_scan"
                    elif self.use_blocknet_randomx:
                        backend_rx = "blocknet_hash_batch"
                    else:
                        backend_rx = "local"

                    if on_stats:
                        on_stats({
                            "hashrate_hs": hps,
                            "threads": self.threads,
                            "accepted": self.accepted,
                            "rejected": self.rejected,
                            "duplicates": self.duplicates,
                            "transport_failures": self.transport_failures,
                            "recovered": self.recovered,
                            "stale_dropped": self.stale_dropped,
                            "last_error": self.last_err,
                            "height": (current_job.height if current_job else None),
                            "job_id": job_id_str,
                            "backend_p2pool": ("blocknet" if self.use_blocknet_p2pool else "stratum"),
                            "backend_randomx": backend_rx,
                            "submit_workers": self.submit_workers,
                            "scan_iters": (
                                self.scan_iters
                                if (
                                    self.use_blocknet_p2pool_scan
                                    or self.use_blocknet_randomx_scan
                                    or self.use_blocknet_gpu_scan
                                )
                                else None
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
                        await cli.keepalived()

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
            await asyncio.gather(*tasks, return_exceptions=True)

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
            self.logger("[Miner] Shutdown complete.")