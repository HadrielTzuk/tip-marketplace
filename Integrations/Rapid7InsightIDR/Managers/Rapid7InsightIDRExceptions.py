class Rapid7InsightIDRException(Exception):
    pass


class NotFoundException(Rapid7InsightIDRException):
    pass


class BadRequestException(Rapid7InsightIDRException):
    pass
