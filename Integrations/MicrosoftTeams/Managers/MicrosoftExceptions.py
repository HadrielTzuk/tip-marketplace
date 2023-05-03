class MicrosoftTeamsManagerError(Exception):
    """
    General Exception for microsoft teams manager
    """
    pass


class MicrosoftTeamsTeamNotFoundError(MicrosoftTeamsManagerError):
    pass


class MicrosoftTeamsChannelNotFoundError(MicrosoftTeamsManagerError):
    pass


class MicrosoftTeamsMessageNotFoundError(MicrosoftTeamsManagerError):
    pass


class MicrosoftTeamsClientError(MicrosoftTeamsManagerError):
    pass
