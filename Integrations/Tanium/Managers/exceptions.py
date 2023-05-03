class TaniumManagerException(Exception):
    pass


class TaniumBadRequestException(TaniumManagerException):
    pass


class TaniumNotFoundException(TaniumManagerException):
    pass


class InvalidTimeException(TaniumManagerException):
    """
    Exception for invalid time
    """
    pass


class FileExistsException(TaniumManagerException):
    pass
