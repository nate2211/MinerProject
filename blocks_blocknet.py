from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from registry import BLOCKS
from blocknet_client import BlockNetClient
from block import BaseBlock

@dataclass
class BlockNetPutBlock(BaseBlock):
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38887"))
        token = str(params.get("token", ""))
        key = str(params.get("key", ""))
        mime = str(params.get("mime", "application/octet-stream"))

        data = payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode("utf-8", errors="replace")
        cli = BlockNetClient(relay=relay, token=token)
        j = cli.put(bytes(data), key=key, mime=mime)
        ref = j.get("ref", "")
        return ref, {"ok": bool(j.get("ok", False)), "response": j}

BLOCKS.register("blocknet_put", BlockNetPutBlock)

@dataclass
class BlockNetStatsBlock(BaseBlock):
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38887"))
        token = str(params.get("token", ""))
        cli = BlockNetClient(relay=relay, token=token)
        j = cli.stats()
        return j, {"ok": bool(j.get("ok", False)), "response": j}

BLOCKS.register("blocknet_stats", BlockNetStatsBlock)

@dataclass
class BlockNetHeartbeatBlock(BaseBlock):
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38887"))
        token = str(params.get("token", ""))
        cid = str(params.get("id", "client1"))

        stats: Dict[str, Any] = {}
        if isinstance(payload, dict):
            stats = payload
        elif payload:
            try:
                stats = json.loads(str(payload))
            except Exception:
                stats = {"payload": str(payload)}

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.heartbeat(cid, stats)
        return j, {"ok": bool(j.get("ok", False)), "response": j}

BLOCKS.register("blocknet_heartbeat", BlockNetHeartbeatBlock)