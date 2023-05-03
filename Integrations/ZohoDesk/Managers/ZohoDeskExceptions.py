class ZohoDeskException(Exception):
    """
    General exception for Zoho Desk
    """
    pass


class ZohoDeskNotFound(ZohoDeskException):
    """
    Not Found Error.
    """
    pass
