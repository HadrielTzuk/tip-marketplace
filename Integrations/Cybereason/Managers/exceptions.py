class CybereasonError(Exception):
    pass


class CybereasonManagerError(CybereasonError):
    pass


class CybereasonManagerNotFoundError(CybereasonError):
    pass


class CybereasonTimeoutError(CybereasonError):
    pass


class CybereasonManagerIsolationError(CybereasonError):
    def __init__(self, message, status="Unknown error"):
        super(CybereasonManagerIsolationError, self).__init__(message)
        self.status = status


class CybereasonNotFoundError(CybereasonError):
    pass


class CybereasonSuccessWithFailureError(CybereasonError):
    pass


class CybereasonClientError(CybereasonError):
    pass


class CybereasonInvalidQueryError(CybereasonError):
    pass


class CybereasonInvalidFormatError(CybereasonError):
    pass
