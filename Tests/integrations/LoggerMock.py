import sys
import datetime


class Logger:
    """Mocks a logger object with info, error, warn and debug methods"""
    def __init__(self) -> None:
        self.timer = datetime.datetime

    def debug(self, msg: str) -> None:
        time = self.timer.utcnow()
        print(f'\nMOCK_{time}_LoggerMock_DEBUG_: {msg}')

    def info(self, msg: str) -> None:
        time = self.timer.utcnow()
        print(f'\nMOCK_{time}_LoggerMock_INFO_: {msg}')

    def warn(self, msg: str) -> None:
        time = self.timer.utcnow()
        print(f'\nMOCK_{time}_LoggerMock_WARNING_: {msg}', file=sys.stderr)

    def error(self, msg: str) -> None:
        time = self.timer.utcnow()
        print(f'\nMOCK_{time}_LoggerMock_ERROR_: {msg}', file=sys.stderr)
