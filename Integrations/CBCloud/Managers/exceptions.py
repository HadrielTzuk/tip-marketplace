class CBCloudException(Exception):
    pass


class CBCloudManagerException(Exception):
    pass


class CBCloudNotFoundError(CBCloudManagerException):
    pass


class CBCloudUnauthorizedError(CBCloudManagerException):
    pass


class CBCloudTimeoutException(CBCloudException):
    pass


class CBCloudConnectorValidationException(Exception):
    pass


class ParameterValidationException(Exception):
    pass
