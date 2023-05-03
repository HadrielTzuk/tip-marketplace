class GoogleBigQueryManagerError(Exception):
    """
    General Exception for Google BigQuery manager
    """
    pass


class GoogleBigQueryValidationError(GoogleBigQueryManagerError):
    """
    General Validation Error raised in Google BigQuery Integration
    """
    pass
