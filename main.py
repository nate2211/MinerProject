from __future__ import annotations

import argparse
import sys

from registry import BLOCKS
import blocks_miner  # registers p2pool_mine

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stratum", default="127.0.0.1:3333")
    ap.add_argument("--wallet", required=True)
    ap.add_argument("--pass", dest="password", default="x")
    ap.add_argument("--threads", type=int, default=1)
    ap.add_argument("--agent", default="py-blockminer/0.1")

    ap.add_argument("--blocknet", dest="blocknet_relay", default="")
    ap.add_argument("--blocknet-token", default="")
    ap.add_argument("--blocknet-id", default="miner1")
    ap.add_argument("--blocknet-key", default="")

    args = ap.parse_args(argv)

    blk = BLOCKS.create("p2pool_mine")
    payload, meta = blk.execute(
        "",
        params={
            "stratum": args.stratum,
            "wallet": args.wallet,
            "pass": args.password,
            "threads": args.threads,
            "agent": args.agent,

            "blocknet_relay": args.blocknet_relay,
            "blocknet_token": args.blocknet_token,
            "blocknet_id": args.blocknet_id,
            "blocknet_key": args.blocknet_key,
        },
    )
    if not meta.get("ok", False):
        print(meta, file=sys.stderr)
        return 2
    print("final:", payload)
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))