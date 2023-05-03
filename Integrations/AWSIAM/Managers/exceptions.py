class AWSIAMStatusCodeException(Exception):
    """
    Status Code exception from AWS IAM manager
    """
    pass


class AWSIAMValidationException(Exception):
    """
    Validation exception from AWS IAM manager
    """
    pass


class AWSIAMEntityAlreadyExistsException(Exception):
    """
    Entity Already Exists exception from AWS IAM manager
    """
    pass


class AWSIAMLimitExceededException(Exception):
    """
    Limit exceeded exception for AWS IAM manager
    """
    pass


class AWSIAMEntityNotFoundException(Exception):
    """
    Not found exception for AWS IAM manager
    """
    pass


class AWSIAMMalformedPolicyDocument(Exception):
    """
    Malformed policy document exception for AWS IAM manager
    """
    pass

class AWSIAMInvalidInputException(Exception):
    """
    Invalid Input exception for AWS IAM manager
    """
    pass