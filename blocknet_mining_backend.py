# blocknet_mining_backend.py
from __future__ import annotations

import asyncio
import base64
import json
import ssl
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

JsonDict = Dict[str, Any]


def _bytes_to_hex(b: bytes) -> str:
    return (b or b"").hex()


def _hex_to_bytes(h: str) -> bytes:
    h = (h or "").strip()
    if len(h) % 2 != 0:
        raise ValueError("hex string must have even length")
    return bytes.fromhex(h)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


@dataclass
class BlockNetApiCfg:
    """
    relay can be:
      - "127.0.0.1:38887"
      - "http://127.0.0.1:38887"
      - "https://example.com:443"
    """
    relay: str
    token: str = ""
    prefix: str = "/v1"
    timeout_s: float = 100
    verify_tls: bool = False
    force_scheme: Optional[str] = None

    def base_url(self) -> str:
        r = (self.relay or "").strip().rstrip("/")
        if "://" not in r:
            scheme = (self.force_scheme or "").strip().lower()
            if not scheme:
                # infer https on port 443, otherwise http
                if r.endswith(":443") or r.split(":")[-1] == "443":
                    scheme = "https"
                else:
                    scheme = "http"
            r = f"{scheme}://{r}"
        return r.rstrip("/")

    def full_url(self, path: str) -> str:
        base = self.base_url()
        pref = (self.prefix or "/v1").strip()
        if not pref.startswith("/"):
            pref = "/" + pref
        pref = pref.rstrip("/")

        p = (path or "").strip()
        if not p.startswith("/"):
            p = "/" + p

        return f"{base}{pref}{p}"


def _make_ssl_context(verify_tls: bool) -> ssl.SSLContext:
    if verify_tls:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post_json_sync(cfg: BlockNetApiCfg, path: str, body: JsonDict) -> JsonDict:
    url = cfg.full_url(path)
    data = json.dumps(body or {}, separators=(",", ":")).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "BlockNetPythonClient/1.0",
    }

    tok = (cfg.token or "").strip()
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
        headers["X-Token"] = tok
        headers["X-BlockNet-Token"] = tok

    req = Request(url, data=data, headers=headers, method="POST")

    ssl_ctx = None
    if urlsplit(url).scheme.lower() == "https":
        ssl_ctx = _make_ssl_context(cfg.verify_tls)

    try:
        with urlopen(req, timeout=float(cfg.timeout_s), context=ssl_ctx) as resp:
            raw = resp.read() or b""
            ct = (resp.headers.get("Content-Type") or "").lower()
            status = getattr(resp, "status", 200)

            if not raw:
                return {"ok": False, "error": "empty response", "status": status, "headers": dict(resp.headers)}

            try:
                j = json.loads(raw.decode("utf-8", errors="replace"))
                if isinstance(j, dict):
                    return j
                return {"ok": False, "error": "json was not an object", "status": status, "value": j}
            except Exception:
                return {
                    "ok": False,
                    "error": "non-json response",
                    "status": status,
                    "headers": dict(resp.headers),
                    "content_type": ct,
                    "body_preview": raw[:4000].decode("utf-8", errors="replace"),
                }

    except HTTPError as e:
        raw = b""
        try:
            raw = e.read() or b""
        except Exception:
            pass
        preview = raw[:4000].decode("utf-8", errors="replace") if raw else ""
        return {
            "ok": False,
            "error": f"http error {getattr(e, 'code', 0)}",
            "status": getattr(e, "code", 0),
            "headers": dict(getattr(e, "headers", {}) or {}),
            "body_preview": preview,
        }
    except URLError as e:
        return {"ok": False, "error": f"connect failed: {e}", "status": 0, "headers": {}}
    except Exception as e:
        return {"ok": False, "error": f"request failed: {e}", "status": 0, "headers": {}}


async def _post_json(cfg: BlockNetApiCfg, path: str, body: JsonDict) -> JsonDict:
    return await asyncio.to_thread(_post_json_sync, cfg, path, body)


class BlockNetP2PoolBackend:
    """
    Docs:
      POST /v1/p2pool/open   {}
      POST /v1/p2pool/poll   {"session":"...", "max_msgs":32}
      POST /v1/p2pool/job    {"session":"..."}
      POST /v1/p2pool/submit {"session":"...","job_id":"...","nonce":"...","result":"..."}
      POST /v1/p2pool/close  {"session":"..."}

      (optional)
      POST /v1/p2pool/scan   {"session":"...","start_nonce":0,"iters":200000,"max_results":4,"nonce_offset":39,"poll_first":false}
    """

    def __init__(self, cfg: BlockNetApiCfg, *, logger: Optional[Callable[[str], None]] = None) -> None:
        self.cfg = cfg
        self.logger = logger or (lambda s: None)
        self.session: str = ""
        self.miner_id: str = ""
        self._opened = False

    async def open(self) -> JsonDict:
        j = await _post_json(self.cfg, "/p2pool/open", {})
        if not j.get("ok"):
            raise RuntimeError(f"BlockNet p2pool open failed: {j}")
        self.session = str(j.get("session") or "")
        self.miner_id = str(j.get("miner_id") or "")
        self._opened = True
        return j.get("job") or {}

    async def poll(self, *, max_msgs: int = 32) -> JsonDict:
        if not self._opened or not self.session:
            raise RuntimeError("p2pool session not open")
        payload: JsonDict = {"session": self.session, "max_msgs": int(max_msgs)}
        j = await _post_json(self.cfg, "/p2pool/poll", payload)
        if not j.get("ok"):
            raise RuntimeError(f"BlockNet p2pool poll failed: {j}")
        return j

    async def job(self) -> JsonDict:
        if not self._opened or not self.session:
            raise RuntimeError("p2pool session not open")
        j = await _post_json(self.cfg, "/p2pool/job", {"session": self.session})
        if not j.get("ok"):
            raise RuntimeError(f"BlockNet p2pool job failed: {j}")
        if j.get("miner_id"):
            self.miner_id = str(j["miner_id"])
        return j.get("job") or {}

    async def get_job(self, *, max_msgs: int = 32) -> JsonDict:
        poll = await self.poll(max_msgs=max_msgs)
        job = poll.get("job") or {}
        if job:
            if poll.get("miner_id"):
                self.miner_id = str(poll["miner_id"])
            return job
        return await self.job()

    async def submit(self, *, job_id: str, nonce_hex: str, result_hex: str) -> JsonDict:
        if not self._opened or not self.session:
            raise RuntimeError("p2pool session not open")
        payload = {
            "session": self.session,
            "job_id": str(job_id),
            "nonce": str(nonce_hex),
            "result": str(result_hex),
        }
        j = await _post_json(self.cfg, "/p2pool/submit", payload)
        if not j.get("ok"):
            raise RuntimeError(f"BlockNet p2pool submit failed: {j}")
        return j

    # -------- NEW: scan (sync+async) --------

    def scan_sync(
        self,
        *,
        start_nonce: int,
        iters: int = 200_000,
        max_results: int = 4,
        nonce_offset: Optional[int] = None,
        poll_first: bool = False,
    ) -> JsonDict:
        if not self._opened or not self.session:
            raise RuntimeError("p2pool session not open")
        payload: JsonDict = {
            "session": self.session,
            "start_nonce": int(start_nonce) & 0xFFFFFFFF,
            "iters": int(iters),
            "max_results": int(max_results),
            "poll_first": bool(poll_first),
        }
        if nonce_offset is not None:
            payload["nonce_offset"] = int(nonce_offset)
        j = _post_json_sync(self.cfg, "/p2pool/scan", payload)
        if not j.get("ok"):
            raise RuntimeError(f"BlockNet p2pool scan failed: {j}")
        return j

    async def scan(
        self,
        *,
        start_nonce: int,
        iters: int = 200_000,
        max_results: int = 4,
        nonce_offset: Optional[int] = None,
        poll_first: bool = False,
    ) -> JsonDict:
        return await asyncio.to_thread(
            self.scan_sync,
            start_nonce=start_nonce,
            iters=iters,
            max_results=max_results,
            nonce_offset=nonce_offset,
            poll_first=poll_first,
        )

    async def close(self) -> None:
        if not self._opened:
            return
        try:
            if self.session:
                await _post_json(self.cfg, "/p2pool/close", {"session": self.session})
        finally:
            self._opened = False
            self.session = ""
            self.miner_id = ""


class BlockNetRandomXHasher:
    """
    Docs:
      POST /v1/randomx/hash
      POST /v1/randomx/hash_batch
      POST /v1/randomx/scan   (optional, if server implements it)
    """

    def __init__(
        self,
        cfg: BlockNetApiCfg,
        *,
        batch_size: int = 64,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.cfg = cfg
        self.logger = logger or (lambda s: None)
        self.batch_size = max(1, int(batch_size))
        self._seed_hex: str = ""

    def set_seed(self, seed_hash: bytes) -> None:
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")
        self._seed_hex = _bytes_to_hex(seed_hash)

    # -------- sync (for worker threads) --------

    def hash_batch_sync(self, items: List[bytes]) -> List[Optional[bytes]]:
        if not self._seed_hex:
            raise RuntimeError("seed not set")
        items = list(items or [])
        if not items:
            return []

        payload = {"seed_hex": self._seed_hex, "items": [{"data_b64": _b64e(bytes(x))} for x in items]}
        j = _post_json_sync(self.cfg, "/randomx/hash_batch", payload)
        if not j.get("ok"):
            raise RuntimeError(f"BlockNet randomx/hash_batch failed: {j}")

        results = j.get("results")
        if not isinstance(results, list):
            raise RuntimeError(f"BlockNet randomx/hash_batch bad results: {j}")

        out: List[Optional[bytes]] = []
        for r in results:
            if isinstance(r, dict) and r.get("ok"):
                try:
                    out.append(_hex_to_bytes(str(r.get("hash_hex") or "")))
                except Exception as e:
                    out.append(None)
                    self.logger(f"[blocknet-rx] bad hash_hex: {e}")
            else:
                err = str(r.get("error") or "") if isinstance(r, dict) else ""
                out.append(None)
                if err:
                    self.logger(f"[blocknet-rx] item failed: {err}")
        return out

    def hash_batch_blob_nonces_sync(
        self,
        *,
        blob: bytes,
        nonce_offset: int,
        nonces_u32: List[int],
    ) -> List[Optional[bytes]]:
        base = bytes(blob or b"")
        off = int(nonce_offset)
        if off < 0 or off + 4 > len(base):
            raise ValueError(f"nonce_offset out of range: {off} for blob_len={len(base)}")

        items: List[bytes] = []
        for n in nonces_u32:
            b = bytearray(base)
            nn = int(n) & 0xFFFFFFFF
            b[off:off + 4] = nn.to_bytes(4, "little", signed=False)
            items.append(bytes(b))

        return self.hash_batch_sync(items)

    # -------- NEW: scan (sync+async) --------

    def scan_sync(
        self,
        *,
        blob: bytes,
        nonce_offset: int,
        start_nonce: int,
        iters: int,
        target64: int,
        max_results: int = 4,
    ) -> JsonDict:
        if not self._seed_hex:
            raise RuntimeError("seed not set")

        b = bytes(blob or b"")
        off = int(nonce_offset)
        if off < 0 or off + 4 > len(b):
            raise ValueError(f"nonce_offset out of range: {off} for blob_len={len(b)}")

        payload: JsonDict = {
            "seed_hex": self._seed_hex,
            "blob_b64": _b64e(b),
            "nonce_offset": off,
            "start_nonce": int(start_nonce) & 0xFFFFFFFF,
            "iters": int(iters),
            "target64": int(target64),
            "max_results": int(max_results),
        }

        j = _post_json_sync(self.cfg, "/randomx/scan", payload)
        if not j.get("ok"):
            raise RuntimeError(f"BlockNet randomx/scan failed: {j}")
        return j

    async def scan(
        self,
        *,
        blob: bytes,
        nonce_offset: int,
        start_nonce: int,
        iters: int,
        target64: int,
        max_results: int = 4,
    ) -> JsonDict:
        return await asyncio.to_thread(
            self.scan_sync,
            blob=blob,
            nonce_offset=nonce_offset,
            start_nonce=start_nonce,
            iters=iters,
            target64=target64,
            max_results=max_results,
        )

    # -------- async helpers (optional) --------

    async def hash_batch(self, items: List[bytes]) -> List[Optional[bytes]]:
        return await asyncio.to_thread(self.hash_batch_sync, items)

    async def hash_batch_blob_nonces(
        self,
        *,
        blob: bytes,
        nonce_offset: int,
        nonces_u32: List[int],
    ) -> List[Optional[bytes]]:
        return await asyncio.to_thread(
            self.hash_batch_blob_nonces_sync,
            blob=blob,
            nonce_offset=nonce_offset,
            nonces_u32=nonces_u32,
        )


class BlockNetGpuScanner:
    """
    Docs:
      POST /v1/gpu/scan

      {
        "seed_hex":"...",
        "blob_hex":"...",
        "nonce_offset":39,
        "start_nonce":0,
        "iters":65536,
        "target64":"18446744073709551615",
        "max_results":16
      }
    """

    def __init__(
        self,
        cfg: BlockNetApiCfg,
        *,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.cfg = cfg
        self.logger = logger or (lambda s: None)

    def scan_sync(
        self,
        *,
        seed_hash: bytes,
        blob: bytes,
        nonce_offset: int,
        start_nonce: int,
        iters: int,
        target64: int,
        max_results: int = 4,
        platform_index: Optional[int] = None,
        device_index: Optional[int] = None,
    ) -> JsonDict:
        seed_hash = bytes(seed_hash or b"")
        blob = bytes(blob or b"")

        if not seed_hash:
            raise ValueError("empty seed_hash")
        if not blob:
            raise ValueError("empty blob")

        off = int(nonce_offset)
        if off < 0 or off + 4 > len(blob):
            raise ValueError(f"nonce_offset out of range: {off} for blob_len={len(blob)}")

        payload: JsonDict = {
            "seed_hex": _bytes_to_hex(seed_hash),
            "blob_hex": _bytes_to_hex(blob),
            "nonce_offset": off,
            "start_nonce": int(start_nonce) & 0xFFFFFFFF,
            "iters": int(iters),
            "target64": str(int(target64)),
            "max_results": int(max_results),
        }

        if platform_index is not None:
            payload["platform_index"] = int(platform_index)
        if device_index is not None:
            payload["device_index"] = int(device_index)

        j = _post_json_sync(self.cfg, "/gpu/scan", payload)
        if not j.get("ok"):
            raise RuntimeError(f"BlockNet gpu/scan failed: {j}")
        return j

    async def scan(
        self,
        *,
        seed_hash: bytes,
        blob: bytes,
        nonce_offset: int,
        start_nonce: int,
        iters: int,
        target64: int,
        max_results: int = 4,
        platform_index: Optional[int] = None,
        device_index: Optional[int] = None,
    ) -> JsonDict:
        return await asyncio.to_thread(
            self.scan_sync,
            seed_hash=seed_hash,
            blob=blob,
            nonce_offset=nonce_offset,
            start_nonce=start_nonce,
            iters=iters,
            target64=target64,
            max_results=max_results,
            platform_index=platform_index,
            device_index=device_index,
        )