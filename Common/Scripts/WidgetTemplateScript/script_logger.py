import datetime
import sys


class Logger:
    """A logger object with info, error, warn and debug methods"""

    def __init__(self) -> None:
        self.timer = datetime.datetime

    def debug(self, msg: str) -> None:
        time = self.timer.utcnow()
        print(f'\n{time}_DEBUG_: {msg}')

    def info(self, msg: str) -> None:
        time = self.timer.utcnow()
        print(f'\n{time}_INFO_: {msg}')

    def warn(self, msg: str) -> None:
        time = self.timer.utcnow()
        print(f'\n{time}_WARNING_: {msg}', file=sys.stderr)

    def error(self, msg: str) -> None:
        time = self.timer.utcnow()
        print(f'\n{time}_ERROR_: {msg}', file=sys.stderr)
