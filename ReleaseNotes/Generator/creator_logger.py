from __future__ import annotations

import datetime
import sys


class Logger:

    def __init__(self) -> None:
        self.timer = datetime.datetime

    def debug(self, msg: str | Exception) -> None:
        time = self.timer.utcnow()
        print(f'{time}_DEBUG_: {msg}')

    def info(self, msg: str | Exception) -> None:
        time = self.timer.utcnow()
        print(f'{time}_INFO_: {msg}')

    def warn(self, msg: str | Exception) -> None:
        time = self.timer.utcnow()
        print(f'{time}_WARNING_: {msg}', file=sys.stderr)

    def error(self, msg: str | Exception) -> None:
        time = self.timer.utcnow()
        print(f'{time}_ERROR_: {msg}', file=sys.stderr)
