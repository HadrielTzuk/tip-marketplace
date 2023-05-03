class JiraManagerError(Exception):
    """
    General Exception for Jira manager
    """
    pass


class JiraValidationError(Exception):
    """
    Validation Exception for Jira Manager
    """
    pass


class JiraGDPRError(Exception):
    """
    GDPR Exception for Jira Manager
    """
    pass

class JiraRelationTypeError(Exception):
    """
    Exception when relation type doesn't exist
    """
    pass