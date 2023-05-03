class ExchangeException(Exception):
    """
    General Exchange Exception
    """
    pass


class ExchangeManagerError(ExchangeException):
    """
    General Exception for file operation manager
    """
    pass


class GetUserReplyException(ExchangeException):
    """
    Exception for get user reply
    """
    pass


class NotFoundEmailsException(ExchangeException):
    """
    Exception for not found emails
    """


class UnableToGetValidEmailFromEntity(Exception):
    pass


class NotFoundAttachmentsException(ExchangeException):
    """
    Exception for not found attachments
    """
    pass


class NotSupportedVersionException(ExchangeException):
    """
    Exception for not supported version
    """
    pass


class TimeoutException(ExchangeException):
    """
    Exception for timeout
    """
    pass


class NotFoundException(ExchangeException):
    """
    Exception for not found case
    """
    pass


class IncompleteInfoException(ExchangeException):
    """
    Exception in case incomplete information
    """
    pass


class InvalidParameterException(ExchangeException):
    """
    Exception in case of invalid parameter
    """
    pass
