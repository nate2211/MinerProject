from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from block import BaseBlock
from registry import BLOCKS
from miner_core import Miner

# import your BlockNet blocks so registry includes them
import blocks_blocknet  # noqa: F401
from registry import BLOCKS as _REG

@dataclass
class P2PoolMineBlock(BaseBlock):
    """
    Params:
      stratum: "host:port" (default "127.0.0.1:3333")
      wallet:  wallet address
      pass:    stratum password (often "x")
      threads: int
      agent:   string

    Optional BlockNet reporting:
      blocknet_relay: "host:port"
      blocknet_token: token
      blocknet_id:    heartbeat id
      blocknet_key:   (optional) key to PUT stats json each interval
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        stratum = str(params.get("stratum", "127.0.0.1:3333"))
        wallet = str(params.get("wallet", "")).strip()
        password = str(params.get("pass", "x"))
        threads = int(params.get("threads", 1))
        agent = str(params.get("agent", "py-blockminer/0.1"))

        if ":" not in stratum:
            return "", {"ok": False, "error": "stratum must be host:port"}
        host, port_s = stratum.rsplit(":", 1)
        port = int(port_s)

        # optional BlockNet
        bn_relay = str(params.get("blocknet_relay", "")).strip()
        bn_token = str(params.get("blocknet_token", "")).strip()
        bn_id = str(params.get("blocknet_id", "miner1")).strip()
        bn_key = str(params.get("blocknet_key", "")).strip()

        heartbeat_block = None
        put_block = None
        if bn_relay:
            heartbeat_block = _REG.create("blocknet_heartbeat")
            if bn_key:
                put_block = _REG.create("blocknet_put")

        miner = Miner(
            stratum_host=host.strip(),
            stratum_port=port,
            wallet=wallet,
            password=password,
            threads=threads,
            agent=agent,
        )

        last_stats: Dict[str, Any] = {}

        def on_stats(stats: Dict[str, Any]) -> None:
            nonlocal last_stats
            last_stats = stats

            if heartbeat_block:
                heartbeat_block.execute(
                    stats,
                    params={"relay": bn_relay, "token": bn_token, "id": bn_id},
                )
            if put_block and bn_key:
                put_block.execute(
                    json.dumps(stats).encode("utf-8"),
                    params={"relay": bn_relay, "token": bn_token, "key": bn_key, "mime": "application/json"},
                )

        try:
            asyncio.run(miner.run(on_stats=on_stats))
        except KeyboardInterrupt:
            miner.stop()
        except Exception as e:
            return "", {"ok": False, "error": str(e), "last_stats": last_stats}

        return last_stats, {"ok": True}

BLOCKS.register("p2pool_mine", P2PoolMineBlock)