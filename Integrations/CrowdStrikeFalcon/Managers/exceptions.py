class CrowdStrikeError(Exception):
    pass


class CrowdStrikeManagerError(CrowdStrikeError):
    pass


class CrowdStrikeStreamError(CrowdStrikeError):
    pass


class CrowdStrikeParameterError(CrowdStrikeError):
    pass


class CrowdStrikeTimeoutError(CrowdStrikeError):
    pass


class CrowdStrikeSessionCreatedError(CrowdStrikeError):
    pass


class CrowdStrikeFalconValidatorException(CrowdStrikeError):
    pass


class NotExistingFilenamesException(CrowdStrikeError):
    pass

class NoSuitableEntitiesException(CrowdStrikeError):
    pass

class FolderNotFoundException(CrowdStrikeError):
    pass

class CrowdStrikeNotFoundError(CrowdStrikeError):
    pass
