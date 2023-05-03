class LogRhythmManagerError(Exception):
    pass


class LogRhythmManagerNotFoundError(LogRhythmManagerError):
    pass


class LogRhythmManagerBadRequestError(LogRhythmManagerError):
    pass


class LogRhythmCasesConnectorException(Exception):
    """
    LogRhythm Cases Connector Exception
    """
    pass
