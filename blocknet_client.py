# blocknet_client.py
from __future__ import annotations

import json
import http.client
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote, urlparse


@dataclass
class BlockNetClient:
    """
    relay:
      - "host:port"
      - "http://host:port"
      - "https://host:port"
      - optionally with a base path: "https://host:port/some/base" (we'll prefix all requests with it)
    token:
      - bearer token (optional)
    """
    relay: str
    token: str = ""
    timeout: int = 60  # seconds

    # ---------------- core parsing / plumbing ----------------

    def _parse(self) -> Tuple[str, str, int, str]:
        """
        Returns: (scheme, host, port, base_path)
        base_path is "" or starts with "/"
        """
        r = (self.relay or "").strip()
        if not r:
            r = "http://127.0.0.1:38888"

        if not (r.startswith("http://") or r.startswith("https://")):
            r = "http://" + r

        u = urlparse(r)
        scheme = (u.scheme or "http").lower()
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if scheme == "https" else 38888)

        # allow reverse-proxy base path
        base_path = (u.path or "").rstrip("/")
        if base_path == "/":
            base_path = ""
        if base_path and not base_path.startswith("/"):
            base_path = "/" + base_path

        return scheme, host, port, base_path

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h: Dict[str, str] = {}
        if self.token:
            t = str(self.token)
            if t.lower().startswith("bearer "):
                h["Authorization"] = t
            else:
                h["Authorization"] = "Bearer " + t
        h["Accept"] = "*/*"
        if extra:
            h.update(extra)
        return h

    def _conn(self) -> Tuple[http.client.HTTPConnection, str]:
        scheme, host, port, base_path = self._parse()
        if scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(host, port, timeout=self.timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
        return conn, base_path

    @staticmethod
    def _normalize_path(base_path: str, path: str) -> str:
        p = (path or "").strip()
        if not p.startswith("/"):
            p = "/" + p
        if base_path:
            if p == "/":
                return base_path + "/"
            return base_path + p
        return p

    def _request(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        headers: Optional[Dict[str, str]] = None,
        *,
        follow_redirects_for_get: bool = True,
    ) -> Tuple[int, Dict[str, str], bytes]:
        """
        Returns: (status, headers, body_bytes)
        Follows redirects for GET (useful for /v1/get?key=... which may redirect).
        """
        conn, base_path = self._conn()
        full_path = self._normalize_path(base_path, path)

        try:
            conn.request(method.upper(), full_path, body=body, headers=self._headers(headers))
            res = conn.getresponse()
            data = res.read() or b""
            status = int(res.status)
            hdrs = dict(res.getheaders())

            # Redirect handling for GET only (safe default)
            if follow_redirects_for_get and method.upper() == "GET" and status in (301, 302, 303, 307, 308):
                loc = res.getheader("Location") or ""
                conn.close()
                if loc:
                    # Location may be absolute or relative
                    if loc.startswith("http://") or loc.startswith("https://"):
                        u = urlparse(loc)
                        new_scheme = u.scheme.lower() or "http"
                        new_host = u.hostname or "127.0.0.1"
                        new_port = u.port or (443 if new_scheme == "https" else 80)
                        new_path = u.path or "/"
                        if u.query:
                            new_path += "?" + u.query

                        if new_scheme == "https":
                            c2 = http.client.HTTPSConnection(new_host, new_port, timeout=self.timeout)
                        else:
                            c2 = http.client.HTTPConnection(new_host, new_port, timeout=self.timeout)

                        try:
                            c2.request("GET", new_path, body=b"", headers=self._headers(headers))
                            r2 = c2.getresponse()
                            d2 = r2.read() or b""
                            return int(r2.status), dict(r2.getheaders()), d2
                        finally:
                            c2.close()
                    else:
                        # relative redirect stays on same relay/base_path
                        return self._request("GET", loc, b"", headers=headers, follow_redirects_for_get=True)

            conn.close()
            return status, hdrs, data
        except Exception as e:
            try:
                conn.close()
            except Exception:
                pass
            msg = str(e).encode("utf-8", errors="replace")
            return 0, {}, msg

    @staticmethod
    def _as_json(status: int, data: bytes, hdrs: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        try:
            j = json.loads(data.decode("utf-8", errors="replace") or "{}")
        except Exception:
            j = {"ok": False, "error": "non-json response"}

        if not isinstance(j, dict):
            j = {"ok": False, "error": "json was not an object", "data": j}

        j.setdefault("status", status)
        if hdrs is not None:
            j.setdefault("headers", hdrs)
        return j

    # ---------------- generic JSON helpers ----------------

    def request_raw(
        self,
        method: str,
        path: str,
        *,
        body: bytes = b"",
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, str], bytes]:
        return self._request(method, path, body=body, headers=headers)

    def request_json(
        self,
        method: str,
        path: str,
        obj: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if obj is None:
            status, hdrs, data = self._request(method, path, body=b"", headers=None)
            return self._as_json(status, data, hdrs)

        body = json.dumps(obj).encode("utf-8")
        status, hdrs, data = self._request(
            method,
            path,
            body=body,
            headers={"Content-Type": "application/json"},
        )
        return self._as_json(status, data, hdrs)

    # ---------------- existing BlockNet endpoints ----------------

    def stats(self) -> Dict[str, Any]:
        status, hdrs, data = self._request("GET", "/v1/stats")
        return self._as_json(status, data, hdrs)

    def heartbeat(self, client_id: str, stats: Dict[str, Any]) -> Dict[str, Any]:
        body = json.dumps({"id": client_id, "stats": stats}).encode("utf-8")
        status, hdrs, data = self._request(
            "POST", "/v1/heartbeat", body,
            headers={"Content-Type": "application/json"},
        )
        return self._as_json(status, data, hdrs)

    def put(self, bytes_data: bytes, *, key: str = "", mime: str = "application/octet-stream") -> Dict[str, Any]:
        headers = {"Content-Type": mime}
        if key:
            headers["X-Blocknet-Key"] = key
        status, hdrs, data = self._request("POST", "/v1/put", bytes_data, headers=headers)
        return self._as_json(status, data, hdrs)

    def get_ref(self, ref: str) -> Tuple[int, Dict[str, str], bytes]:
        return self._request("GET", f"/v1/get/{ref}")

    def get_key(self, key: str) -> Tuple[int, Dict[str, str], bytes]:
        return self._request("GET", f"/v1/get?key={quote(key)}")

    # ---------------- API module wrappers (prefix-aware) ----------------

    @staticmethod
    def _pfx(prefix: str) -> str:
        p = (prefix or "/v1").strip()
        if not p.startswith("/"):
            p = "/" + p
        return p.rstrip("/")

    # core
    def api_ping(self, *, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("GET", f"{p}/ping", None)

    def api_texttovec(
        self,
        text: str,
        *,
        dim: int = 1024,
        normalize: bool = True,
        output: str = "b64f32",
        prefix: str = "/v1",
    ) -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/texttovec", {
            "text": text,
            "dim": int(dim),
            "normalize": bool(normalize),
            "output": str(output),
        })

    def api_vectortext(self, body: Dict[str, Any], *, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/vectortext", dict(body))

    # media
    def api_imagetovec(self, body: Dict[str, Any], *, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/imagetovec", dict(body))

    def api_videotovec(self, body: Dict[str, Any], *, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/videotovec", dict(body))

    # randomx
    def api_randomx_status(self, *, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("GET", f"{p}/randomx/status", None)

    def api_randomx_hash(self, body: Dict[str, Any], *, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/randomx/hash", dict(body))

    def api_randomx_hash_batch(self, body: Dict[str, Any], *, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/randomx/hash_batch", dict(body))
    # web
    def api_web_fetch(self, body: Dict[str, Any], *, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/web/fetch", dict(body))

    def api_web_js(self, body: Dict[str, Any], *, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/web/js", dict(body))

    def api_web_links(self, body: dict, *, prefix: str = "/v1") -> dict:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/web/links", dict(body))

    def api_web_rss_find(self, body: dict, *, prefix: str = "/v1") -> dict:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/web/rss_find", dict(body))

    def api_p2pool_open(self, *, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/p2pool/open", {})

    def api_p2pool_job(self, session: str, *, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/p2pool/job", {"session": session})

    def api_p2pool_poll(self, session: str, *, max_msgs: int = 32, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/p2pool/poll", {"session": session, "max_msgs": int(max_msgs)})

    def api_p2pool_submit(self, body: Dict[str, Any], *, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/p2pool/submit", dict(body))

    def api_p2pool_close(self, session: str, *, prefix: str = "/v1") -> Dict[str, Any]:
        p = self._pfx(prefix)
        return self.request_json("POST", f"{p}/p2pool/close", {"session": session})
