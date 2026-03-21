from __future__ import annotations

import asyncio
import contextlib
import json
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

    Expected pool flow:
      - connect()
      - login(wallet, password, agent)
      - next_job() in a loop
      - submit(...) as shares are found
      - keepalived() periodically
      - close() on shutdown
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        logger=None,
        connect_timeout: float = 10.0,
        request_timeout: float = 30.0,
        reconnect_initial_delay: float = 1.0,
        reconnect_max_delay: float = 15.0,
        max_job_queue: int = 32,
    ) -> None:
        self.host = str(host)
        self.port = int(port)
        self.logger = logger or (lambda s: None)

        self.connect_timeout = float(connect_timeout)
        self.request_timeout = float(request_timeout)
        self.reconnect_initial_delay = float(reconnect_initial_delay)
        self.reconnect_max_delay = float(reconnect_max_delay)
        self.max_job_queue = max(1, int(max_job_queue))

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

        self._reader_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None

        self._conn_lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()

        self._connected_evt = asyncio.Event()
        self._logged_in_evt = asyncio.Event()
        self._closed = False

        self._req_id = 0
        self._pending: Dict[int, asyncio.Future] = {}

        self._jobs: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=self.max_job_queue)
        self._last_job_key: Optional[Tuple[str, str, str, str]] = None
        self._current_job: Dict[str, Any] = {}

        self._client_id: str = ""
        self._login_creds: Optional[Tuple[str, str, str]] = None
        self._auto_login_enabled = False

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
                await asyncio.sleep(0.2)

        self._auto_login_enabled = False
        if last_exc:
            raise last_exc
        raise StratumDisconnected("login failed because the connection was lost")

    async def next_job(self) -> Dict[str, Any]:
        while not self._closed:
            await self._ensure_logged_in()
            try:
                job = await asyncio.wait_for(self._jobs.get(), timeout=30.0)
                if job:
                    return job
            except asyncio.TimeoutError:
                # Stay alive and let reconnect logic do its work if needed.
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
        return await self._rpc("keepalived", {"id": self._client_id})

    async def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        self._connected_evt.clear()
        self._logged_in_evt.clear()
        self._auto_login_enabled = False
        self._client_id = ""

        reconnect_task = self._reconnect_task
        self._reconnect_task = None
        if reconnect_task:
            reconnect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await reconnect_task

        reader_task = self._reader_task
        self._reader_task = None
        if reader_task:
            reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await reader_task

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
            await asyncio.sleep(0.05)

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
            await asyncio.sleep(0.05)

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
                self.logger(f"[Stratum] reconnect failed: {e}")
                await self._shutdown_transport()
                self._connected_evt.clear()
                self._logged_in_evt.clear()
                self._client_id = ""

            await asyncio.sleep(delay)
            delay = min(self.reconnect_max_delay, delay * 2.0)

    async def _open_socket(self) -> None:
        self.logger(f"[Stratum] Connecting to {self.host}:{self.port}...")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port),
            timeout=self.connect_timeout,
        )

        self._reader = reader
        self._writer = writer
        self._connected_evt.set()
        self.logger("[Stratum] Connected.")

        old_reader_task = self._reader_task
        self._reader_task = None
        if old_reader_task and not old_reader_task.done():
            old_reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await old_reader_task

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

    async def _rpc(self, method: str, params: Dict[str, Any]) -> Any:
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

        except Exception as e:
            self._pending.pop(req_id, None)
            await self._handle_disconnect(f"send failed during {method}: {e}")
            raise StratumDisconnected(f"send failed during {method}: {e}") from e

        try:
            return await asyncio.wait_for(fut, timeout=self.request_timeout)
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

                try:
                    msg = json.loads(line.decode("utf-8", errors="replace"))
                except Exception as e:
                    self.logger(f"[Stratum] Ignoring malformed JSON line: {e}")
                    continue

                await self._handle_message(msg)

        except asyncio.CancelledError:
            raise
        except Exception as e:
            if not self._closed:
                self.logger(f"[Stratum] Reader stopped: {e}")
                await self._handle_disconnect(str(e))

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
                await reader_task

        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await writer.wait_closed()

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

        jid = str(job.get("job_id") or "")
        if jid:
            self.logger(f"[Stratum] New job received: {jid}")