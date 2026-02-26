from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Tuple

@dataclass
class BaseBlock:
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        raise NotImplementedError