class AWSEC2StatusCodeException(Exception):
    """
    Status Code exception from AWS EC2 manager
    """
    pass


class AWSEC2ValidationException(Exception):
    """
    Status Code exception from AWS EC2 manager
    """
    pass


class AWSEC2EmptyResultsException(Exception):
    """
    Status Code exception from AWS EC2 manager
    """
    pass


class AWSEC2IncorrectInstanceStateException(Exception):
    """
    Incorrect Instance State exception from AWS EC2 manager
    """
    pass


class AWSEC2InvalidInstanceIDException(Exception):
    """
    Invalid Instance ID exception from AWS EC2 manager
    """
    pass


class AWSEC2InvalidParameterValueException(Exception):
    """
    Invalid Invalid Parameter Value exception from AWS EC2 manager
    """
    pass


class AWSEC2LimitExceededException(Exception):
    """
    Limit Exceeded exception from AWS EC2 manager
    """
    pass


class AWSEC2InvalidSecurityGroupException(Exception):
    """
    Invalid Security Group Exception exception from AWS EC2 manager
    """
    pass


class AWSEC2NotFoundException(Exception):
    """
    Not Found exception for AWS EC2 manager
    """
    pass


class AWSEC2UnknownIpPermissions(Exception):
    """
    Unknown Ip Permission for AWS EC2 manager
    """
    pass
