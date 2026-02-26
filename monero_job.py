from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

def _hex_to_bytes(h: str) -> bytes:
    h = (h or "").strip()
    return bytes.fromhex(h) if h else b""

def parse_target64_from_hex(target_hex: str) -> int:
    """
    XMRig stratum target is commonly 4 bytes (8 hex chars).
    XMRig converts 32-bit target -> 64-bit internal target. :contentReference[oaicite:6]{index=6}
    """
    tb = _hex_to_bytes(target_hex)
    if len(tb) == 4:
        raw32 = int.from_bytes(tb, "little", signed=False)
        if raw32 == 0:
            return 0
        # mirrors XMRig Job::setTarget() conversion :contentReference[oaicite:7]{index=7}
        # target64 = 0xFFFFFFFFFFFFFFFF / (0xFFFFFFFF / raw32)
        return (0xFFFFFFFFFFFFFFFF // (0xFFFFFFFF // raw32))
    if len(tb) == 8:
        return int.from_bytes(tb, "little", signed=False)
    # fallback: treat as big integer (rare)
    return int.from_bytes(tb, "little", signed=False) if tb else 0

@dataclass(frozen=True)
class MoneroJob:
    job_id: str
    blob: bytes
    seed_hash: bytes
    target64: int
    algo: str
    height: int | None

    # For rx/0, XMRig uses nonce offset 39 :contentReference[oaicite:8]{index=8}
    nonce_offset: int = 39

    @staticmethod
    def from_stratum(job: Dict[str, Any]) -> "MoneroJob":
        return MoneroJob(
            job_id=str(job.get("job_id") or ""),
            blob=_hex_to_bytes(str(job.get("blob") or "")),
            seed_hash=_hex_to_bytes(str(job.get("seed_hash") or "")),
            target64=parse_target64_from_hex(str(job.get("target") or "")),
            algo=str(job.get("algo") or "rx/0"),
            height=(int(job["height"]) if "height" in job and str(job["height"]).isdigit() else None),
        )

def set_nonce(blob: bytes, *, nonce_offset: int, nonce_u32: int) -> bytes:
    """
    Writes 4-byte nonce (little endian) into the stratum blob.
    For rx/0 pools this offset is 39. :contentReference[oaicite:9]{index=9}
    """
    if len(blob) < nonce_offset + 4:
        raise ValueError(f"blob too short for nonce offset {nonce_offset}: len={len(blob)}")
    b = bytearray(blob)
    b[nonce_offset:nonce_offset+4] = int(nonce_u32).to_bytes(4, "little", signed=False)
    return bytes(b)