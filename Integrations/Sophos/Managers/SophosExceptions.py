class SophosManagerError(Exception):
    """
    General Exception for Sophos manager
    """
    pass


class BadRequestError(SophosManagerError):
    pass

class HashAlreadyOnBlocklist(SophosManagerError):
    pass