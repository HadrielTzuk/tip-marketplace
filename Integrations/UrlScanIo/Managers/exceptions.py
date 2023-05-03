class UrlScanError(Exception):
    """
    General Exception for UrlScan manager
    """
    pass


class UrlDnsScanError(UrlScanError):
    pass


class SuitableEntitiesNotFoundException(Exception):
    pass
