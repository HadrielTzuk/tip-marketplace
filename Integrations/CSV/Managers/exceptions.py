class CSVException(Exception):
    pass


class CSVManagerException(CSVException):
    pass


class CSVEncodingException(CSVManagerException):
    pass


class CSVInvalidColumnException(CSVManagerException):
    pass


class CSVConnectorException(CSVException):
    pass
