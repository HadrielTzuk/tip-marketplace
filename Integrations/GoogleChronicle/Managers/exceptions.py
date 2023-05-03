class GoogleChronicleManagerError(Exception):
    """
    General Exception for Google Chronicle manager
    """
    pass


class GoogleChronicleAPILimitError(Exception):
    """
    API Limit Exception for Google Chronicle manager
    """
    pass


class GoogleChronicleValidationError(Exception):
    """
    Validation Exception for Google Chronicle manager
    """
    pass


class InvalidTimeException(Exception):
    """
    Exception for invalid time
    """
    pass


class GoogleChronicleBadRequestError(Exception):
    """
    Exception for Bad Request
    """
    pass
