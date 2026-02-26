from __future__ import annotations

import asyncio
import queue
import secrets
import threading
import time
import traceback
import struct
from ctypes import c_uint32, c_ubyte, byref, POINTER, cast
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from monero_job import MoneroJob
from randomx_ctypes import RandomX
from stratum_client import StratumClient


@dataclass
class Share:
    job_id: str
    nonce_u32: int
    result32: bytes

    @property
    def nonce_hex(self) -> str:
        return int(self.nonce_u32).to_bytes(4, "little").hex()

    @property
    def result_hex(self) -> str:
        return self.result32.hex()


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


class Miner:
    def __init__(self, *, stratum_host: str, stratum_port: int, wallet: str, password: str, threads: int = 1,
                 agent: str = "py-blockminer/1.0") -> None:
        self.stratum_host = stratum_host
        self.stratum_port = stratum_port
        self.wallet = wallet
        self.password = password
        self.threads = max(1, int(threads))
        self.agent = agent

        self.job_state = JobState()
        self.share_q: "queue.Queue[Share]" = queue.Queue()
        self._stop = threading.Event()

        # Load RandomX immediately
        print("[Miner] Initializing RandomX...")
        self.rx = RandomX()

        self._hashes = 0
        self._hash_mu = threading.Lock()
        self.accepted = 0
        self.rejected = 0
        self.last_err: str = ""

    def stop(self) -> None:
        """Signal all threads and loops to stop immediately."""
        print("[Miner] Stop signal received.")
        self._stop.set()

    def add_hashes(self, n: int) -> None:
        with self._hash_mu:
            self._hashes += n

    def pop_hashes(self) -> int:
        with self._hash_mu:
            h = self._hashes
            self._hashes = 0
            return h

    def _worker(self, idx: int) -> None:
        print(f"[Worker-{idx}] Started.")
        vm = None
        try:
            last_seq = 0
            cur_job: Optional[MoneroJob] = None
            nonce = secrets.randbits(32)

            # Pre-allocate C buffer to avoid Python overhead in loop
            blob_buf = None
            nonce_ptr = None

            while not self._stop.is_set():
                # Check for new job
                seq, job = self.job_state.wait(last_seq, timeout=0.1)

                if self._stop.is_set():
                    break

                if job is None:
                    continue

                if seq != last_seq:
                    # --- NEW JOB LOGIC ---
                    cur_job = job
                    last_seq = seq

                    # 1. Initialize Dataset (Heavy)
                    # We check stop flag before heavy lift
                    if self._stop.is_set(): break
                    self.rx.ensure_seed(cur_job.seed_hash)

                    # 2. Create VM
                    if vm is not None:
                        self.rx.destroy_vm(vm)
                        vm = None
                    vm = self.rx.create_vm()

                    # 3. Optimization: Prepare Mutable C Buffer
                    # Copy job blob into a mutable C byte array
                    blob_buf = (c_ubyte * len(cur_job.blob)).from_buffer_copy(cur_job.blob)

                    # Get a pointer directly to the nonce offset (usually 39)
                    # This allows us to update nonce in C speed, not Python speed
                    offset = cur_job.nonce_offset
                    nonce_ptr = cast(byref(blob_buf, offset), POINTER(c_uint32))

                if vm is None or blob_buf is None:
                    continue

                # --- FAST MINING LOOP ---
                batch_size = 500  # Increased batch size for speed

                for _ in range(batch_size):
                    # Inlining the stop check for performance
                    if self._stop.is_set() or self.job_state._seq != last_seq:
                        break

                    nonce = (nonce + 1) & 0xFFFFFFFF

                    # DIRECT MEMORY WRITE (Fast!)
                    nonce_ptr[0] = nonce

                    # HASH
                    h32 = self.rx.hash(vm, blob_buf)

                    # CHECK TARGET
                    # (int.from_bytes is fast enough in Python 3.10+)
                    value = int.from_bytes(h32[24:32], "little", signed=False)
                    if value < cur_job.target64:
                        print(f"[Worker-{idx}] SHARE FOUND! Nonce: {nonce}")
                        self.share_q.put(Share(job_id=cur_job.job_id, nonce_u32=nonce, result32=h32))

                self.add_hashes(batch_size)

        except Exception as e:
            self.last_err = f"Worker {idx} crashed: {e}"
            print(f"[Worker-{idx}] FATAL ERROR: {e}")
            traceback.print_exc()
        finally:
            if vm: self.rx.destroy_vm(vm)
            print(f"[Worker-{idx}] Stopped.")

    async def run(self, *, on_stats: Optional[callable] = None) -> None:
        cli = StratumClient(self.stratum_host, self.stratum_port)

        try:
            print(f"[Miner] Connecting to {self.stratum_host}:{self.stratum_port}...")
            await cli.connect()
            print("[Miner] Connected. Logging in...")

            login = await cli.login(wallet=self.wallet, password=self.password, agent=self.agent)
            print(f"[Miner] Logged in. Client ID: {login.client_id}")

            self.job_state.set(MoneroJob.from_stratum(login.job))

            # Start CPU Threads
            threads = []
            for i in range(self.threads):
                t = threading.Thread(target=self._worker, args=(i,), name=f"Worker-{i}", daemon=True)
                t.start()
                threads.append(t)

            # --- ASYNC TASKS ---

            async def job_loop() -> None:
                while not self._stop.is_set():
                    j = await cli.next_job()
                    self.job_state.set(MoneroJob.from_stratum(j))

            async def submit_loop() -> None:
                while not self._stop.is_set():
                    try:
                        # Check queue, timeout 0.5s to allow checking _stop
                        share = await asyncio.to_thread(self.share_q.get, True, 0.5)
                        try:
                            await cli.submit(job_id=share.job_id, nonce_hex=share.nonce_hex,
                                             result_hex=share.result_hex)
                            self.accepted += 1
                            print("[Miner] Share accepted!")
                        except Exception as e:
                            self.rejected += 1
                            print(f"[Miner] Share rejected: {e}")
                    except queue.Empty:
                        continue

            async def stats_loop() -> None:
                last_t = time.time()
                while not self._stop.is_set():
                    # Check stop button every 0.1s instead of sleeping 2s
                    for _ in range(20):
                        if self._stop.is_set(): return
                        await asyncio.sleep(0.1)

                    now = time.time()
                    hps = self.pop_hashes() / (now - last_t)
                    last_t = now

                    # Fetch the current job to grab the ID
                    current_job = self.job_state.get()
                    job_id_str = current_job.job_id if current_job else ""

                    print(f"[Stats] {hps:.2f} H/s | A:{self.accepted} R:{self.rejected} | Job:{job_id_str[:8]}")

                    if on_stats:
                        on_stats({
                            "hashrate_hs": hps,
                            "threads": self.threads,
                            "accepted": self.accepted,
                            "rejected": self.rejected,
                            "last_error": self.last_err,
                            "height": (current_job.height if current_job else None),
                            "job_id": job_id_str,  # <--- Added this back in
                        })

            async def keepalive_loop() -> None:
                while not self._stop.is_set():
                    for _ in range(300):  # 30 seconds check
                        if self._stop.is_set(): return
                        await asyncio.sleep(0.1)
                    await cli.keepalived()

            # --- RUN UNTIL STOP ---
            tasks = [
                asyncio.create_task(job_loop()),
                asyncio.create_task(submit_loop()),
                asyncio.create_task(stats_loop()),
                asyncio.create_task(keepalive_loop())
            ]

            # Wait here until STOP flag is set
            while not self._stop.is_set():
                await asyncio.sleep(0.1)

            print("[Miner] Shutting down tasks...")
            for t in tasks: t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        finally:
            print("[Miner] Closing connection...")
            await cli.close()
            self._stop.set()  # Ensure threads know
            print("[Miner] Shutdown complete.")