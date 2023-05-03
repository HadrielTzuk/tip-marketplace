class Outpost24GeneralException(Exception):
    """
    General exception for Outpost24
    """
    pass

class DeviceNotFoundError(Exception):
    """
    Exception for Outpost24 when no device - hostname or IP Aaddress is not found
    """
    pass