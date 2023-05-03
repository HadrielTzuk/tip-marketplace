class QRadarError(Exception):
    pass


class QRadarCorrelationsEventsConnectorException(Exception):
    """
    QRadar Correlations Events Connector Exception
    """
    pass


class QRadarConnectorValidationException(QRadarError):
    pass


class QRadarApiError(QRadarError):
    """
    General Exception for QRadar api wrapper
    """
    pass


class QRadarRequestError(QRadarError):
    """
    General Exception for QRadar requests.
    """
    pass


class QRadarNotFoundError(QRadarError):
    pass


class QRadarValidationError(QRadarError):
    pass


class QRadarCustomFieldValidation(QRadarError):
    pass


class QRadarInvalidRuleException(QRadarError):
    pass
