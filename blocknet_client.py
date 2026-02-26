# blocknet_client.py
from __future__ import annotations

import json
import http.client
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse


@dataclass
class BlockNetClient:
    relay: str               # "host:port" or "http://host:port"
    token: str = ""

    def _parse(self) -> Tuple[str, int]:
        r = self.relay.strip()
        if not (r.startswith("http://") or r.startswith("https://")):
            r = "http://" + r
        u = urlparse(r)
        host = u.hostname or "127.0.0.1"
        port = u.port or 38888
        return host, port

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h: Dict[str, str] = {}
        if self.token:
            h["Authorization"] = "Bearer " + self.token
        if extra:
            h.update(extra)
        return h

    def _request(self, method: str, path: str, body: bytes = b"", headers: Optional[Dict[str, str]] = None):
        host, port = self._parse()
        conn = http.client.HTTPConnection(host, port, timeout=60)
        conn.request(method, path, body=body, headers=self._headers(headers))
        res = conn.getresponse()
        data = res.read()
        # Handle redirect for GET (your earlier issue)
        if res.status in (301, 302, 303, 307, 308) and method.upper() == "GET":
            loc = res.getheader("Location") or ""
            if loc:
                conn.close()
                return self._request("GET", loc, b"", headers)
        conn.close()
        return res.status, dict(res.getheaders()), data

    def stats(self) -> dict:
        status, hdrs, data = self._request("GET", "/v1/stats")
        return self._as_json(status, data)

    def heartbeat(self, client_id: str, stats: dict) -> dict:
        body = json.dumps({"id": client_id, "stats": stats}).encode("utf-8")
        status, hdrs, data = self._request(
            "POST", "/v1/heartbeat", body,
            headers={"Content-Type": "application/json"},
        )
        return self._as_json(status, data)

    def put(self, bytes_data: bytes, *, key: str = "", mime: str = "application/octet-stream") -> dict:
        headers = {"Content-Type": mime}
        if key:
            headers["X-Blocknet-Key"] = key
        status, hdrs, data = self._request("POST", "/v1/put", bytes_data, headers=headers)
        return self._as_json(status, data)

    def get_ref(self, ref: str) -> Tuple[int, Dict[str, str], bytes]:
        return self._request("GET", f"/v1/get/{ref}")

    def get_key(self, key: str) -> Tuple[int, Dict[str, str], bytes]:
        # server may 302 redirect; client follows it
        from urllib.parse import quote
        return self._request("GET", f"/v1/get?key={quote(key)}")

    @staticmethod
    def _as_json(status: int, data: bytes) -> dict:
        try:
            j = json.loads(data.decode("utf-8", errors="replace") or "{}")
        except Exception:
            j = {"ok": False, "error": "non-json response", "status": status}
        if isinstance(j, dict) and "status" not in j:
            j["status"] = status
        return j
