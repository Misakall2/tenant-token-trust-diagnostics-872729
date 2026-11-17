"""可注入时钟。

缓存到期判断与声明时间校验全部走这个时钟，测试时替换为可控时钟，
生产环境使用系统时钟。
"""

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> int:
        """返回当前 Unix 时间戳（秒，整数）。"""


class SystemClock:
    """生产环境时钟。"""

    def now(self) -> int:
        return int(time.time())


class ControlledClock:
    """测试用可控时钟，时间只能通过 advance/set 显式推进。"""

    def __init__(self, start: int = 1_800_000_000) -> None:
        self._now = start

    def now(self) -> int:
        return self._now

    def set(self, timestamp: int) -> None:
        self._now = timestamp

    def advance(self, seconds: int) -> None:
        if seconds < 0:
            raise ValueError("clock can only move forward")
        self._now += seconds
