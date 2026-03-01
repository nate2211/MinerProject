# miner_core.py
from __future__ import annotations

import asyncio
import queue
import secrets
import threading
import time
import traceback
from ctypes import c_uint32, c_ubyte, byref, POINTER, cast
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

    def set(self, job: MoneroJob) -> None:
        with self._cv:
            self._job = job
            self._seq += 1
            self._cv.notify_all()

    def wait(self, last_seq: int, timeout: float = 0.5) -> Tuple[int, Optional[MoneroJob]]:
        with self._cv:
            if self._seq == last_seq:
                self._cv.wait(timeout=timeout)
            return self._seq, self._job

    def get(self) -> Optional[MoneroJob]:
        with self._mu:
            return self._job

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

        blocknet_api_relay: str = "",
        blocknet_api_token: str = "",
        blocknet_api_prefix: str = "/v1",
        blocknet_verify_tls: bool = False,

        randomx_batch_size: int = 64,
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

        self._bn_cfg: Optional[BlockNetApiCfg] = None
        self._bn_p2pool: Optional[BlockNetP2PoolBackend] = None
        self._bn_rx: Optional[BlockNetRandomXHasher] = None
        self._rx_batch = max(1, int(randomx_batch_size))

        if self.use_blocknet_p2pool or self.use_blocknet_randomx:
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

        if self.use_blocknet_randomx:
            assert self._bn_cfg is not None
            self.logger("[Miner] Using BlockNet RandomX API for hashing...")
            self._bn_rx = BlockNetRandomXHasher(self._bn_cfg, batch_size=self._rx_batch, logger=self.logger)
            self.rx: Optional[RandomX] = None
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

        try:
            last_seq = 0
            cur_job: Optional[MoneroJob] = None
            nonce = secrets.randbits(32)

            blob_buf = None
            nonce_ptr = None

            while not self._stop.is_set():
                seq, job = self.job_state.wait(last_seq, timeout=0.1)

                if self._stop.is_set():
                    break
                if job is None:
                    continue

                if seq != last_seq:
                    cur_job = job
                    last_seq = seq

                    if self._stop.is_set():
                        break

                    if not self.use_blocknet_randomx:
                        if not self.rx:
                            raise RuntimeError("local RandomX not initialized")

                        self.rx.ensure_seed(cur_job.seed_hash)

                        if vm is not None:
                            self.rx.destroy_vm(vm)
                            vm = None
                        vm = self.rx.create_vm()

                        blob_buf = (c_ubyte * len(cur_job.blob)).from_buffer_copy(cur_job.blob)
                        offset = cur_job.nonce_offset
                        nonce_ptr = cast(byref(blob_buf, offset), POINTER(c_uint32))
                    else:
                        # Remote hashing: no local VM/buffer
                        if vm is not None and self.rx:
                            self.rx.destroy_vm(vm)
                        vm = None
                        blob_buf = None
                        nonce_ptr = None

                if cur_job is None:
                    continue

                # ------------------- mining loop -------------------

                if self.use_blocknet_randomx:
                    # Remote hashing batch (SYNC call inside this worker thread)
                    batch_n = self._rx_batch
                    nonces: List[int] = []

                    for _ in range(batch_n):
                        if self._stop.is_set() or self.job_state.seq != last_seq:
                            break
                        nonce = (nonce + 1) & 0xFFFFFFFF
                        nonces.append(nonce)

                    if not nonces:
                        continue

                    try:
                        assert self._bn_rx is not None
                        self._bn_rx.set_seed(cur_job.seed_hash)

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
                                # IMPORTANT: shares still go through SAME queue + submit_loop
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

                    batch_size = 500
                    done = 0

                    for _ in range(batch_size):
                        if self._stop.is_set() or self.job_state.seq != last_seq:
                            break

                        nonce = (nonce + 1) & 0xFFFFFFFF
                        nonce_ptr[0] = nonce

                        h32 = self.rx.hash(vm, blob_buf)

                        value = int.from_bytes(h32[24:32], "little", signed=False)
                        if value < cur_job.target64:
                            self.logger(f"[Worker-{idx}] SHARE FOUND! Nonce: {nonce}")
                            self.share_q.put(Share(job_id=cur_job.job_id, nonce_u32=nonce, result32=h32))

                        done += 1

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

            # ---------------- start CPU workers ----------------
            for i in range(self.threads):
                t = threading.Thread(target=self._worker, args=(i,), name=f"Worker-{i}", daemon=True)
                t.start()

            # ---------------- async tasks ----------------

            async def job_loop() -> None:
                last_job_id = ""
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
                            await asyncio.sleep(0.5)

                        await asyncio.sleep(0.25)
                    else:
                        assert cli is not None
                        j = await cli.next_job()
                        self.job_state.set(MoneroJob.from_stratum(j))

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
                            "backend_randomx": ("blocknet" if self.use_blocknet_randomx else "local"),
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