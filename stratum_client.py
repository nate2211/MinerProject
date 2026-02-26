from __future__ import annotations

import asyncio
import json
import logging
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

# Set up simple console logging to see what's happening
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

JsonDict = Dict[str, Any]


@dataclass
class StratumLoginResult:
    client_id: str
    job: JsonDict
    extensions: Tuple[str, ...]


class StratumClient:
    """
    Robust JSON-RPC-over-TCP stratum client.
    """

    def __init__(self, host: str, port: int, *, timeout: float = 30.0, logger = None) -> None:
        self.logger = logger
        self.host = host
        self.port = port
        self.timeout = timeout

        self._r: asyncio.StreamReader | None = None
        self._w: asyncio.StreamWriter | None = None

        self._next_id = 1
        self._pending: Dict[int, asyncio.Future] = {}
        self._jobs: asyncio.Queue[JsonDict] = asyncio.Queue()
        self._closed = False

        self._client_id: str = ""
        self._extensions: Tuple[str, ...] = ()

    async def connect(self) -> None:
        self.logger(f"[stratum] Connecting to {self.host}:{self.port}...")
        try:
            self._r, self._w = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )
            self.logger("[stratum] Connected!")
        except Exception as e:
            raise RuntimeError(f"Could not connect to {self.host}:{self.port} -> {e}")

        # Start the background listener
        asyncio.create_task(self._read_loop())

    async def close(self) -> None:
        self._closed = True
        if self._w:
            try:
                self._w.close()
                await self._w.wait_closed()
            except Exception:
                pass

    async def _send(self, obj: JsonDict) -> None:
        if not self._w or self._closed:
            raise RuntimeError("Not connected")
        try:
            # Stratum uses newline-delimited JSON
            line = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
            self._w.write(line)
            await self._w.drain()
        except Exception as e:
            self._closed = True
            raise RuntimeError(f"Send failed: {e}")

    async def call(self, method: str, params: Optional[JsonDict] = None) -> JsonDict:
        if self._closed:
            raise RuntimeError("Connection is closed")

        rid = self._next_id
        self._next_id += 1

        fut = asyncio.get_running_loop().create_future()
        self._pending[rid] = fut

        req: JsonDict = {"id": rid, "method": method}
        if params is not None:
            req["params"] = params

        try:
            await self._send(req)
            # Wait for response with timeout
            return await asyncio.wait_for(fut, timeout=self.timeout)
        except asyncio.TimeoutError:
            # Clean up the pending future if we timed out
            self._pending.pop(rid, None)
            raise RuntimeError(f"Stratum request '{method}' timed out (pool did not reply)")
        except Exception as e:
            self._pending.pop(rid, None)
            raise e

    async def _read_loop(self) -> None:
        """
        Background task: reads lines from the socket and dispatches them.
        """
        assert self._r is not None
        while not self._closed:
            try:
                # Read line (blocking until data comes or disconnect)
                line_bytes = await self._r.readline()
                if not line_bytes:
                    # Empty bytes means the server closed the connection
                    self.logger("[stratum] Server closed connection (EOF)")
                    break

                line = line_bytes.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    self.logger(f"[stratum] Warning: Ignored garbage data: {line[:50]}...")
                    continue

                # 1. Is it a Response to our request? (Has 'id')
                if "id" in msg and msg["id"] is not None:
                    rid = int(msg["id"])
                    if rid in self._pending:
                        fut = self._pending.pop(rid)
                        if not fut.done():
                            if msg.get("error"):
                                error_info = msg.get("error")
                                fut.set_exception(RuntimeError(f"Pool Error: {error_info}"))
                            else:
                                fut.set_result(msg)
                    continue

                # 2. Is it a Notification? (method="job")
                if msg.get("method") == "job":
                    params = msg.get("params") or {}
                    await self._jobs.put(params)
                    continue

            except Exception as e:
                self.logger(f"[stratum] Read loop error: {e}")
                break

        # Cleanup when loop exits
        self._closed = True
        # Cancel any requests waiting for an answer
        for rid, fut in list(self._pending.items()):
            if not fut.done():
                fut.set_exception(RuntimeError("Connection lost during request"))
        self._pending.clear()

    async def login(self, *, wallet: str, password: str, agent: str = "py-blockminer/0.1",
                    algos: Optional[list[str]] = None) -> StratumLoginResult:
        if algos is None:
            algos = ["rx/0"]

        self.logger(f"[stratum] Logging in as {wallet[:6]}...")
        # XMRig-compatible login
        resp = await self.call("login", {
            "login": wallet,
            "pass": password,
            "agent": agent,
            "algo": algos,
        })

        # XMRig pools return {result: {id, job, extensions, ...}}
        result = resp.get("result")
        if not result or not isinstance(result, dict):
            # Fallback: some pools put data directly in response or structure it differently
            raise RuntimeError(f"Login failed or unexpected response: {resp}")

        cid = str(result.get("id") or "")
        job = result.get("job")
        exts = tuple(result.get("extensions") or [])

        if not job:
            self.logger("[stratum] Login successful, waiting for first job...")

        self._client_id = cid
        self._extensions = exts

        return StratumLoginResult(client_id=cid, job=job or {}, extensions=exts)

    async def next_job(self) -> JsonDict:
        return await self._jobs.get()

    async def submit(self, *, job_id: str, nonce_hex: str, result_hex: str) -> JsonDict:
        if not self._client_id:
            raise RuntimeError("not logged in")
        return await self.call("submit", {
            "id": self._client_id,
            "job_id": job_id,
            "nonce": nonce_hex,
            "result": result_hex,
        })

    async def keepalived(self) -> None:
        if not self._client_id:
            return
        try:
            await self.call("keepalived", {"id": self._client_id})
        except Exception:
            pass

    @property
    def extensions(self) -> Tuple[str, ...]:
        return self._extensions