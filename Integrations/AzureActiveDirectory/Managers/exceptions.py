class AzureADError(Exception):
    """
    General Exception for AzureAD manager
    """
    pass


class AzureADNotFoundError(AzureADError):
    """
    Azure AD not found Exception
    """
    pass


class AzurePasswordComplexityError(AzureADError):
    """
    Azure AD Password Complexity Exception
    """
    pass


class AzureWrongFiltersError(AzureADError):
    """
    Azure AD Wrong Filters Exception
    """
    pass
