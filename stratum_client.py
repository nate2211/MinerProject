from __future__ import annotations

import asyncio
import contextlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class LoginResponse:
    client_id: str
    job: Dict[str, Any]


class StratumError(RuntimeError):
    pass


class StratumDisconnected(StratumError):
    pass


class StratumProtocolError(StratumError):
    pass


class StratumRpcError(StratumError):
    def __init__(self, message: str, *, code: Any = None, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.data = data


class StratumClient:
    """
    Monero-style JSON-RPC stratum client with automatic reconnect/re-login.

    Keepalive behavior in this version:
      - only sends keepalive when the connection has actually been idle
      - does not force a reconnect on the first keepalive timeout if recent RX activity exists
      - only disconnects after repeated keepalive timeouts with no recent activity
    """

    _CLOSED_JOB = {"__closed__": True}

    def __init__(
        self,
        host: str,
        port: int,
        *,
        logger=None,
        connect_timeout: float = 10.0,
        request_timeout: float = 30.0,
        keepalive_timeout: float = 12.0,
        reconnect_initial_delay: float = 1.0,
        reconnect_max_delay: float = 15.0,
        max_job_queue: int = 32,
        wait_poll_interval: float = 0.05,
        close_timeout: float = 2.0,
        keepalive_idle_threshold: float = 45.0,
        keepalive_activity_grace: float = 90.0,
        keepalive_disconnect_after_misses: int = 3,
    ) -> None:
        self.host = str(host)
        self.port = int(port)
        self.logger = logger or (lambda s: None)

        self.connect_timeout = float(connect_timeout)
        self.request_timeout = float(request_timeout)
        self.keepalive_timeout = max(1.0, float(keepalive_timeout))
        self.reconnect_initial_delay = float(reconnect_initial_delay)
        self.reconnect_max_delay = float(reconnect_max_delay)
        self.max_job_queue = max(1, int(max_job_queue))
        self.wait_poll_interval = max(0.01, float(wait_poll_interval))
        self.close_timeout = max(0.1, float(close_timeout))

        self.keepalive_idle_threshold = max(1.0, float(keepalive_idle_threshold))
        self.keepalive_activity_grace = max(self.keepalive_idle_threshold, float(keepalive_activity_grace))
        self.keepalive_disconnect_after_misses = max(1, int(keepalive_disconnect_after_misses))

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

        self._reader_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None

        self._conn_lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()

        self._connected_evt = asyncio.Event()
        self._logged_in_evt = asyncio.Event()
        self._job_evt = asyncio.Event()
        self._closed = False

        self._req_id = 0
        self._pending: Dict[int, asyncio.Future] = {}

        self._jobs: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=self.max_job_queue)
        self._last_job_key: Optional[Tuple[str, str, str, str]] = None
        self._current_job: Dict[str, Any] = {}

        self._client_id: str = ""
        self._login_creds: Optional[Tuple[str, str, str]] = None
        self._auto_login_enabled = False

        now = time.monotonic()
        self._last_rx_at = now
        self._last_tx_at = now
        self._last_activity_at = now
        self._keepalive_miss_count = 0

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def is_connected(self) -> bool:
        w = self._writer
        return bool(self._connected_evt.is_set() and w is not None and not w.is_closing())

    @property
    def is_logged_in(self) -> bool:
        return bool(self._logged_in_evt.is_set() and self._client_id)

    def _note_rx(self) -> None:
        now = time.monotonic()
        self._last_rx_at = now
        self._last_activity_at = now
        self._keepalive_miss_count = 0

    def _note_tx(self) -> None:
        now = time.monotonic()
        self._last_tx_at = now
        self._last_activity_at = now

    def seconds_since_rx(self) -> float:
        return max(0.0, time.monotonic() - self._last_rx_at)

    def seconds_since_activity(self) -> float:
        return max(0.0, time.monotonic() - self._last_activity_at)

    def should_send_keepalive(self) -> bool:
        return self.seconds_since_activity() >= self.keepalive_idle_threshold

    async def connect(self) -> None:
        await self._ensure_connected()

    async def login(self, *, wallet: str, password: str, agent: str) -> LoginResponse:
        self._login_creds = (str(wallet), str(password), str(agent))

        last_exc: Optional[BaseException] = None
        for _ in range(3):
            await self._ensure_connected()
            try:
                resp = await self._perform_login(is_reconnect=False)
                self._auto_login_enabled = True
                return resp
            except StratumDisconnected as e:
                last_exc = e
                if self._closed:
                    break
                await asyncio.sleep(0.2)

        self._auto_login_enabled = False
        if last_exc:
            raise last_exc
        raise StratumDisconnected("login failed because the connection was lost")

    async def next_job(self) -> Dict[str, Any]:
        while not self._closed:
            await self._ensure_logged_in()

            try:
                while True:
                    job = self._jobs.get_nowait()
                    if job is self._CLOSED_JOB or (isinstance(job, dict) and job.get("__closed__")):
                        raise StratumDisconnected("client closed")
                    if job:
                        return job
            except asyncio.QueueEmpty:
                pass

            self._job_evt.clear()
            try:
                await asyncio.wait_for(self._job_evt.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

        raise StratumDisconnected("client closed")

    async def submit(self, *, job_id: str, nonce_hex: str, result_hex: str) -> Any:
        params = {
            "id": self._client_id,
            "job_id": str(job_id),
            "nonce": str(nonce_hex),
            "result": str(result_hex),
        }

        last_exc: Optional[BaseException] = None
        for attempt in range(2):
            await self._ensure_logged_in()
            params["id"] = self._client_id
            try:
                return await self._rpc("submit", params)
            except StratumDisconnected as e:
                last_exc = e
                if self._closed:
                    break
                if attempt == 0:
                    self.logger("[Stratum] submit interrupted by disconnect; retrying after reconnect...")
                    await asyncio.sleep(0.2)
                    continue
                raise

        if last_exc:
            raise last_exc
        raise StratumDisconnected("submit failed")

    async def keepalived(self) -> Any:
        await self._ensure_logged_in()

        if not self.should_send_keepalive():
            return {
                "skipped": True,
                "reason": "recent_activity",
                "idle_seconds": self.seconds_since_activity(),
            }

        try:
            result = await self._rpc(
                "keepalived",
                {"id": self._client_id},
                timeout=self.keepalive_timeout,
                disconnect_on_timeout=False,
            )
            self._keepalive_miss_count = 0
            return result
        except asyncio.TimeoutError:
            self._keepalive_miss_count += 1
            recent_rx = self.seconds_since_rx() < self.keepalive_activity_grace

            if recent_rx and self._keepalive_miss_count < self.keepalive_disconnect_after_misses:
                self.logger(
                    "[Stratum] keepalive timed out but recent server activity was seen; "
                    "keeping connection alive."
                )
                return {
                    "skipped": True,
                    "reason": "timeout_but_recent_rx",
                    "misses": self._keepalive_miss_count,
                    "seconds_since_rx": self.seconds_since_rx(),
                }

            await self._handle_disconnect("keepalived timed out")
            raise StratumDisconnected("keepalived timed out")

    async def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        self._connected_evt.clear()
        self._logged_in_evt.clear()
        self._auto_login_enabled = False
        self._client_id = ""
        self._job_evt.set()
        self._wake_job_waiters()

        reconnect_task = self._reconnect_task
        self._reconnect_task = None
        if reconnect_task:
            reconnect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(reconnect_task, timeout=self.close_timeout)

        reader_task = self._reader_task
        self._reader_task = None
        if reader_task:
            reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(reader_task, timeout=self.close_timeout)

        await self._shutdown_transport()
        self._fail_all_pending(StratumDisconnected("client closed"))

    async def _ensure_connected(self) -> None:
        if self._closed:
            raise StratumDisconnected("client closed")

        if self.is_connected:
            return

        self._schedule_reconnect()

        while not self._closed:
            if self.is_connected:
                return
            await asyncio.sleep(self.wait_poll_interval)

        raise StratumDisconnected("client closed")

    async def _ensure_logged_in(self) -> None:
        if self._closed:
            raise StratumDisconnected("client closed")

        if self.is_logged_in:
            return

        if not self._login_creds:
            raise StratumProtocolError("not logged in; call login() first")

        self._schedule_reconnect()

        while not self._closed:
            if self.is_logged_in:
                return
            await asyncio.sleep(self.wait_poll_interval)

        raise StratumDisconnected("client closed")

    def _schedule_reconnect(self) -> None:
        if self._closed:
            return
        if self._reconnect_task and not self._reconnect_task.done():
            return
        self._reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def _reconnect_loop(self) -> None:
        delay = self.reconnect_initial_delay

        while not self._closed:
            try:
                async with self._conn_lock:
                    if self.is_connected and (self.is_logged_in or not self._auto_login_enabled):
                        return

                    await self._open_socket()

                    if self._auto_login_enabled and self._login_creds:
                        await self._perform_login(is_reconnect=True)

                    return

            except asyncio.CancelledError:
                raise
            except Exception as e:
                if self._closed:
                    return
                self.logger(f"[Stratum] reconnect failed: {self._format_exc(e)}")
                await self._shutdown_transport()
                self._connected_evt.clear()
                self._logged_in_evt.clear()
                self._client_id = ""
                self._job_evt.set()

            await asyncio.sleep(delay)
            delay = min(self.reconnect_max_delay, delay * 2.0)

    async def _open_socket(self) -> None:
        self.logger(f"[Stratum] Connecting to {self.host}:{self.port}...")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port),
            timeout=self.connect_timeout,
        )

        if self._closed:
            with contextlib.suppress(Exception):
                writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            raise StratumDisconnected("client closed during connect")

        self._reader = reader
        self._writer = writer
        self._connected_evt.set()

        now = time.monotonic()
        self._last_rx_at = now
        self._last_tx_at = now
        self._last_activity_at = now
        self._keepalive_miss_count = 0

        self.logger("[Stratum] Connected.")

        old_reader_task = self._reader_task
        self._reader_task = None
        if old_reader_task and not old_reader_task.done():
            old_reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(old_reader_task, timeout=self.close_timeout)

        self._reader_task = asyncio.create_task(self._reader_loop())

    async def _perform_login(self, *, is_reconnect: bool) -> LoginResponse:
        if not self._login_creds:
            raise StratumProtocolError("missing login credentials")

        wallet, password, agent = self._login_creds

        result = await self._rpc(
            "login",
            {
                "login": wallet,
                "pass": password,
                "agent": agent,
            },
        )

        if not isinstance(result, dict):
            raise StratumProtocolError(f"login result was not a dict: {result!r}")

        client_id = str(result.get("id") or result.get("client_id") or "")
        if not client_id:
            raise StratumProtocolError(f"login response missing client id: {result!r}")

        job = result.get("job") or {}
        if not isinstance(job, dict):
            job = {}

        self._client_id = client_id
        self._logged_in_evt.set()
        self._current_job = job or self._current_job

        if job:
            self._push_job(job)

        if is_reconnect:
            self.logger("[Stratum] Reconnected and logged in again.")
        else:
            self.logger("[Stratum] Login successful.")

        return LoginResponse(client_id=client_id, job=job)

    async def _rpc(
        self,
        method: str,
        params: Dict[str, Any],
        timeout: Optional[float] = None,
        *,
        disconnect_on_timeout: bool = True,
    ) -> Any:
        await self._ensure_connected()

        loop = asyncio.get_running_loop()
        req_id = self._next_request_id()
        fut = loop.create_future()
        self._pending[req_id] = fut

        payload = {
            "id": req_id,
            "method": method,
            "params": params,
        }
        line = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")

        try:
            async with self._send_lock:
                writer = self._writer
                if writer is None or writer.is_closing():
                    raise StratumDisconnected("writer is not available")

                writer.write(line)
                await writer.drain()
                self._note_tx()

        except Exception as e:
            self._pending.pop(req_id, None)
            await self._handle_disconnect(f"send failed during {method}: {self._format_exc(e)}")
            raise StratumDisconnected(f"send failed during {method}: {self._format_exc(e)}") from e

        wait_timeout = self.request_timeout if timeout is None else float(timeout)

        try:
            return await asyncio.wait_for(fut, timeout=wait_timeout)
        except asyncio.TimeoutError:
            self._pending.pop(req_id, None)
            if disconnect_on_timeout:
                await self._handle_disconnect(f"{method} timed out")
                raise StratumDisconnected(f"{method} timed out")
            raise
        finally:
            self._pending.pop(req_id, None)

    async def _reader_loop(self) -> None:
        try:
            while not self._closed:
                reader = self._reader
                if reader is None:
                    raise StratumDisconnected("reader missing")

                line = await reader.readline()
                if not line:
                    raise StratumDisconnected("server closed the connection")

                self._note_rx()

                try:
                    msg = json.loads(line.decode("utf-8", errors="replace"))
                except Exception as e:
                    self.logger(f"[Stratum] Ignoring malformed JSON line: {self._format_exc(e)}")
                    continue

                await self._handle_message(msg)

        except asyncio.CancelledError:
            raise
        except Exception as e:
            if not self._closed:
                self.logger(f"[Stratum] Reader stopped: {self._format_exc(e)}")
                await self._handle_disconnect(self._format_exc(e))

    async def _handle_message(self, msg: Dict[str, Any]) -> None:
        if not isinstance(msg, dict):
            return

        method = msg.get("method")
        if method == "job":
            params = msg.get("params") or {}
            if isinstance(params, dict):
                self._push_job(params)
            return

        if "id" in msg:
            try:
                rid = int(msg["id"])
            except Exception:
                return

            fut = self._pending.get(rid)
            if fut is None or fut.done():
                return

            error = msg.get("error")
            if error:
                if isinstance(error, dict):
                    fut.set_exception(
                        StratumRpcError(
                            str(error.get("message") or "RPC error"),
                            code=error.get("code"),
                            data=error.get("data"),
                        )
                    )
                else:
                    fut.set_exception(StratumRpcError(str(error)))
                return

            fut.set_result(msg.get("result"))
            return

    async def _handle_disconnect(self, reason: str) -> None:
        if self._closed:
            return

        was_connected = self.is_connected or self._connected_evt.is_set() or self._logged_in_evt.is_set()
        self._connected_evt.clear()
        self._logged_in_evt.clear()
        self._client_id = ""
        self._job_evt.set()

        await self._shutdown_transport()
        self._fail_all_pending(StratumDisconnected(f"connection lost: {reason}"))

        if was_connected:
            self.logger(f"[Stratum] Disconnected: {reason}")

        if self._auto_login_enabled and not self._closed:
            self._schedule_reconnect()

    async def _shutdown_transport(self) -> None:
        writer = self._writer
        self._reader = None
        self._writer = None

        current = asyncio.current_task()
        reader_task = self._reader_task
        self._reader_task = None

        if reader_task and reader_task is not current:
            reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(reader_task, timeout=self.close_timeout)

        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=self.close_timeout)

    def _fail_all_pending(self, exc: BaseException) -> None:
        pending = list(self._pending.values())
        self._pending.clear()
        for fut in pending:
            if not fut.done():
                fut.set_exception(exc)

    def _next_request_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _job_key(self, job: Dict[str, Any]) -> Tuple[str, str, str, str]:
        return (
            str(job.get("job_id") or ""),
            str(job.get("blob") or ""),
            str(job.get("target") or ""),
            str(job.get("seed_hash") or ""),
        )

    def _push_job(self, job: Dict[str, Any]) -> None:
        if not isinstance(job, dict) or not job:
            return

        key = self._job_key(job)
        if key == self._last_job_key:
            return

        self._last_job_key = key
        self._current_job = job

        while self._jobs.full():
            with contextlib.suppress(asyncio.QueueEmpty):
                self._jobs.get_nowait()

        with contextlib.suppress(asyncio.QueueFull):
            self._jobs.put_nowait(job)

        self._job_evt.set()

        jid = str(job.get("job_id") or "")
        if jid:
            self.logger(f"[Stratum] New job received: {jid}")

    def _wake_job_waiters(self) -> None:
        self._job_evt.set()
        while self._jobs.full():
            with contextlib.suppress(asyncio.QueueEmpty):
                self._jobs.get_nowait()
        with contextlib.suppress(asyncio.QueueFull):
            self._jobs.put_nowait(self._CLOSED_JOB)

    @staticmethod
    def _format_exc(exc: BaseException) -> str:
        text = str(exc).strip()
        return text or exc.__class__.__name__
