class LastlineAPIException(Exception):
    """
    Lastline API exception
    """
    pass


class LastlineAuthenticationException(Exception):
    """
    Lastline Authentication exception
    """
    pass


class LastlinePermissionException(Exception):
    """
    Lastline Authentication exception
    """
    pass


class LastlineInvalidParamException(Exception):
    """
    Lastline Invalid Parameter exception
    """
    pass


class LastlineManyRequestsException(Exception):
    """
    Lastline Too Many Requests exception
    """
    pass
