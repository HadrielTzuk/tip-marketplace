class IllusiveNetworksException(Exception):
    pass


class IncidentNotReadyException(Exception):
    pass


class RateLimitException(Exception):
    pass


class ManagerNotFoundException(IllusiveNetworksException):
    pass


class ManagerAlreadyExistException(IllusiveNetworksException):
    pass
