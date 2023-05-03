class GoogleGKEManagerError(Exception):
    """
    General Exception for Google Kubernetes Engine manager
    """
    pass


class GoogleGKEManagerCriticalError(Exception):
    """
    Critical Exception for Google Kubernetes Engine manager
    """
    pass


class GoogleGKEProjectLookupError(GoogleGKEManagerCriticalError):
    """
    Project Lookup Exception for Google Kubernetes Engine manager
    """
    pass


class GoogleGKENotFoundError(GoogleGKEManagerError):
    """
    Not Found Exception for Google Kubernetes Engine manager
    """
    pass


class GoogleGKEInvalidRequestArgumentError(GoogleGKEManagerError):
    """
    Invalid Request Argument Exception for Google Kubernetes Engine manager
    """
    pass


class GoogleGKEInvalidZoneError(GoogleGKEInvalidRequestArgumentError):
    """
    Invalid Zone Exception for Google Kubernetes Engine manager
    """
    pass


class GoogleGKEInvalidClusterNameError(GoogleGKEInvalidRequestArgumentError):
    """
    Exception for Invalid Cluster Name for Google Kubernetes Engine manager
    """
    pass


class GoogleGKEInvalidNodePoolNameError(GoogleGKEInvalidRequestArgumentError):
    """
    Exception for Invalid Cluster Node Pool Name for Google Kubernetes Engine manager
    """
    pass


class GoogleGKEInvalidOperationNameError(GoogleGKEInvalidRequestArgumentError):
    """
    Exception for Invalid Operation Name for Google Kubernetes Engine manager
    """
    pass


class NegativeValueException(Exception):
    """
    Exception for negative value
    """
    pass


class NonPositiveValueException(Exception):
    """
    Exception for non positive value
    """
    pass


class InvalidJSONFormatException(Exception):
    """
    Exception for invalid JSON format
    """
    pass


class MissingParametersException(Exception):
    """
    Exception for missing parameters
    """
    pass
