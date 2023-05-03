class VirusTotalException(Exception):
    pass


class ForceRaiseException(VirusTotalException):
    pass


class UnauthorizedException(ForceRaiseException):
    pass


class VirusTotalNotFoundException(VirusTotalException):
    pass


class VirusTotalLimitReachedException(VirusTotalException):
    pass


class VirusTotalBadRequest(VirusTotalException):
    pass


class MissingEntitiesException(VirusTotalException):
    pass


class VirusTotalInvalidFormat(VirusTotalException):
    pass


class VirusTotalInvalidApiKeyException(VirusTotalException):
    pass


class VirusTotalPermissionException(VirusTotalException):
    pass
