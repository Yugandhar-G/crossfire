"""Guardian mode state management -- MONITOR or BLOCK."""

from typing import Literal


class Guardian:
    def __init__(self):
        self.mode: Literal["monitor", "block"] = "monitor"

    def set_mode(self, mode: str) -> str:
        if mode in ("monitor", "block"):
            self.mode = mode
        return self.mode

    def to_dict(self) -> dict:
        return {"mode": self.mode}
