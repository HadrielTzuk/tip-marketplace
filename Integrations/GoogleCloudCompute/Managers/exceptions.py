class GoogleCloudComputeManagerError(Exception):
    """
    General Exception for Google Cloud Compute manager
    """
    pass


class GoogleCloudComputeAPILimitError(Exception):
    """
    API Limit Exception for Google Cloud Compute manager
    """
    pass


class GoogleCloudComputeValidationError(Exception):
    """
    Validation Exception for Google Cloud Compute manager
    """
    pass


class GoogleCloudComputeInvalidZone(Exception):
    """
    Invalid Zone Exception for Google Cloud Compute manager
    """
    pass


class GoogleCloudTransportException(Exception):
    """
    Transport Exception for Google Cloud Compute manager
    """
    pass


class GoogleCloudAuthenticationError(Exception):
    """
    Google Cloud Compute Authentication Error for Google Cloud Compute manager
    """
    pass


class GoogleCloudComputeInvalidInstanceID(Exception):
    """
    Google Cloud Compute Invalid Instance ID Error for Google Cloud Compute manager
    """
    pass


class GoogleCloudPolicyJSONError(Exception):
    """
    Google Cloud Compute Invalid IAM Policy JSON Error for Google Cloud Compute manager
    """
    pass


class GoogleCloudComputeLabelsValidationError(Exception):
    """
    Validation Exception for labels for Google Cloud Compute manager
    """
    pass
