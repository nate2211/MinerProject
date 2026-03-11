# miner_core.py
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
from stratum_client import StratumClient

from blocknet_mining_backend import BlockNetApiCfg, BlockNetP2PoolBackend, BlockNetRandomXHasher



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

        # NEW: shared nonce allocator (prevents overlap across worker threads)
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

        # NEW: server-side scanning modes
        use_blocknet_p2pool_scan: bool = False,   # calls /p2pool/scan (requires p2pool session)
        use_blocknet_randomx_scan: bool = False,  # calls /randomx/scan (blob+target provided)

        # BlockNet API config
        blocknet_api_relay: str = "",
        blocknet_api_token: str = "",
        blocknet_api_prefix: str = "/v1",
        blocknet_verify_tls: bool = False,

        # RandomX batch hashing config
        randomx_batch_size: int = 64,

        # NEW: scan tuning
        scan_iters: int = 1000,
        scan_max_results: int = 4,
        scan_poll_first: bool = False,     # only used by /p2pool/scan
        scan_nonce_offset: Optional[int] = None,  # override nonce offset (else job.nonce_offset)
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

        self.scan_iters = max(1, int(scan_iters))
        self.scan_max_results = max(1, int(scan_max_results))
        self.scan_poll_first = bool(scan_poll_first)
        self.scan_nonce_offset = scan_nonce_offset if scan_nonce_offset is None else int(scan_nonce_offset)


        if self.use_blocknet_p2pool_scan and not self.use_blocknet_p2pool:
            raise RuntimeError("use_blocknet_p2pool_scan=True requires use_blocknet_p2pool=True")

        # If p2pool_scan is enabled, we do NOT need local RandomX nor /randomx/hash_batch
        if self.use_blocknet_p2pool_scan:
            self.use_blocknet_randomx = False
            self.use_blocknet_randomx_scan = False

        self._bn_cfg: Optional[BlockNetApiCfg] = None
        self._bn_p2pool: Optional[BlockNetP2PoolBackend] = None
        self._bn_rx: Optional[BlockNetRandomXHasher] = None
        self._rx_batch = max(1, int(randomx_batch_size))

        need_blocknet = self.use_blocknet_p2pool or self.use_blocknet_randomx or self.use_blocknet_randomx_scan
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
        self.last_err: str = ""

        # Setup hashing backends
        if self.use_blocknet_randomx or self.use_blocknet_randomx_scan:
            assert self._bn_cfg is not None
            if self.use_blocknet_randomx_scan:
                self.logger("[Miner] Using BlockNet RandomX SCAN API (/randomx/scan)...")
            else:
                self.logger("[Miner] Using BlockNet RandomX API (/randomx/hash_batch)...")
            self._bn_rx = BlockNetRandomXHasher(self._bn_cfg, batch_size=self._rx_batch, logger=self.logger)
            self.rx: Optional[RandomX] = None
        else:
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
                    # job changed: reset local VM/buffers if used
                    if not self.use_blocknet_randomx and not self.use_blocknet_randomx_scan and not self.use_blocknet_p2pool_scan:
                        if not self.rx:
                            raise RuntimeError("local RandomX not initialized")
                        rx_hash_into = self.rx.hash_into
                        # ---- only rebuild VM when seed changes ----
                        seed_changed = (last_seed != cur_job.seed_hash)
                        self.rx.ensure_seed(cur_job.seed_hash)

                        if seed_changed or vm is None:
                            if vm is not None:
                                self.rx.destroy_vm(vm)
                            vm = self.rx.create_vm()
                            last_seed = cur_job.seed_hash

                        # ---- reuse blob buffer; just copy new blob bytes ----
                        if blob_buf is None or len(blob_buf) != len(cur_job.blob):
                            blob_buf = (c_ubyte * len(cur_job.blob))()
                        memmove(blob_buf, cur_job.blob, len(cur_job.blob))

                        offset = cur_job.nonce_offset
                        nonce_ptr = cast(byref(blob_buf, offset), POINTER(c_uint32))
                    else:
                        rx_hash_into = None
                        # remote modes: no local VM/buffer
                        if vm is not None and self.rx:
                            self.rx.destroy_vm(vm)
                        vm = None
                        blob_buf = None
                        nonce_ptr = None

                if cur_job is None:
                    continue

                # ------------------- mining loop -------------------

                if self.use_blocknet_p2pool_scan:
                    # Server-side scan via /p2pool/scan
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
                                        self.logger(f"[Worker-{idx}] SHARE FOUND! Nonce: {n}")
                                        share_put(Share(job_id=job_id, nonce_u32=n, result32=h32))
                                except Exception:
                                    continue

                        if done <= 0:
                            time.sleep(0.05)

                    except Exception as e:
                        self.last_err = f"p2pool scan failed: {e}"
                        self.logger(f"[Worker-{idx}] p2pool scan error: {e}")
                        time.sleep(0.25)

                elif self.use_blocknet_randomx_scan:
                    # Server-side scan via /randomx/scan (blob+target provided)
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
                                        self.share_q.put(Share(job_id=cur_job.job_id, nonce_u32=n, result32=h32))
                                except Exception:
                                    continue

                        if done <= 0:
                            time.sleep(0.05)

                    except Exception as e:
                        self.last_err = f"randomx scan failed: {e}"
                        self.logger(f"[Worker-{idx}] randomx scan error: {e}")
                        time.sleep(0.25)

                elif self.use_blocknet_randomx:
                    # Remote hashing batch (/randomx/hash_batch)
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
                                self.logger(f"[Worker-{idx}] SHARE FOUND! Nonce: {n}")
                                self.share_q.put(Share(job_id=cur_job.job_id, nonce_u32=n, result32=h32))

                        if valid_hashes:
                            self.add_hashes(valid_hashes)
                        else:
                            time.sleep(0.05)

                    except Exception as e:
                        self.last_err = f"remote hash failed: {e}"
                        self.logger(f"[Worker-{idx}] remote hash error: {e}")
                        time.sleep(0.25)

                else:

                    # Local hashing
                    if vm is None or blob_buf is None or nonce_ptr is None or self.rx is None:
                        continue
                    batch_size = 1024
                    done = 0

                    target = cur_job.target64
                    job_id = cur_job.job_id

                    # (optional) check stop/job-change only every 64 iters to cut overhead
                    for i in range(batch_size):
                        if (i & 15) == 0 and (self._stop.is_set() or self.job_state.seq != last_seq):
                            break

                        nonce = (nonce_base + (nonce_i + i) * stride) & 0xFFFFFFFF
                        nonce_ptr[0] = nonce

                        rx_hash_into(vm, blob_buf, out_buf)
                        if value64.value < target:
                            self.logger(f"[Worker-{idx}] SHARE FOUND! Nonce: {nonce}")
                            share_put(Share(job_id=job_id, nonce_u32=nonce, result32=bytes(out_buf)))
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

        # create backends
        if self.use_blocknet_p2pool:
            assert self._bn_cfg is not None
            self._bn_p2pool = BlockNetP2PoolBackend(self._bn_cfg, logger=self.logger)
        else:
            cli = StratumClient(self.stratum_host, self.stratum_port, logger=self.logger)

        try:
            # ---------------- connect + initial job ----------------
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

            # ---------------- start worker threads ----------------
            for i in range(self.threads):
                t = threading.Thread(target=self._worker, args=(i,), name=f"Worker-{i}", daemon=True)
                t.start()

            # ---------------- async tasks ----------------

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
                            self.last_err = f"p2pool poll error: {e}"
                            self.logger(f"[Miner] p2pool poll error: {e}")
                            await asyncio.sleep(0.05)

                        await asyncio.sleep(0.05)
                    else:
                        assert cli is not None
                        j = await cli.next_job()
                        mj = MoneroJob.from_stratum(j)
                        # Only update workers if something meaningful changed
                        key = (mj.seed_hash, mj.target64, mj.blob)
                        if key != last_key:
                            last_key = key
                            self.job_state.set(mj)

            async def submit_loop() -> None:
                while not self._stop.is_set():
                    try:
                        share = await asyncio.to_thread(self.share_q.get, True, 0.5)
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
                            self.logger("[Miner] Share accepted!")
                        except Exception as e:
                            self.rejected += 1
                            self.logger(f"[Miner] Share rejected: {e}")
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
                    last_t = now

                    current_job = self.job_state.get()
                    job_id_str = current_job.job_id if current_job else ""

                    if self.use_blocknet_p2pool_scan:
                        backend_rx = "blocknet_p2pool_scan"
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
                            "last_error": self.last_err,
                            "height": (current_job.height if current_job else None),
                            "job_id": job_id_str,
                            "backend_p2pool": ("blocknet" if self.use_blocknet_p2pool else "stratum"),
                            "backend_randomx": backend_rx,
                            "scan_iters": (self.scan_iters if (self.use_blocknet_p2pool_scan or self.use_blocknet_randomx_scan) else None),
                        })

            async def keepalive_loop() -> None:
                if self.use_blocknet_p2pool:
                    # HTTP polling keeps the session alive; nothing else required
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
                asyncio.create_task(submit_loop()),
                asyncio.create_task(stats_loop()),
                asyncio.create_task(keepalive_loop()),
            ]

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