from TIPCommon import unix_now


class Microsoft365DefenderException(Exception):
    """
    General exception for Microsoft 365 Defender
    """
    pass

class TooManyRequestsError(Microsoft365DefenderException):
    def __init__(self, *args):
        self.encountered_at = unix_now()
        super(Microsoft365DefenderException, self).__init__(*args)

class NotFoundItemException(Microsoft365DefenderException):
    pass
  
class NotEnoughEntitiesException(Microsoft365DefenderException):
    pass

class APIPermissionError(Microsoft365DefenderException):
    pass
