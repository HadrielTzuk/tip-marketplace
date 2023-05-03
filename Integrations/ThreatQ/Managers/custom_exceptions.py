class ThreatQManagerException(Exception):
    pass


class ObjectNotFoundException(ThreatQManagerException):
    pass


class LinkObjectsException(ThreatQManagerException):
    pass


class ListRelatedObjectsException(ThreatQManagerException):
    pass


class MalwareDetailsException(ThreatQManagerException):
    pass


class MalwareDetailsNotFoundException(ThreatQManagerException):
    pass


class SourceObjectNotFoundException(ObjectNotFoundException):
    pass


class DestinationObjectNotFoundException(ObjectNotFoundException):
    pass


class RelatedObjectNotFoundException(ObjectNotFoundException):
    pass


class ObjectCreateException(ThreatQManagerException):
    pass


class EventCreateException(ThreatQManagerException):
    pass


class IndicatorScoreException(ThreatQManagerException):
    pass


class InvalidFieldException(ThreatQManagerException):
    pass