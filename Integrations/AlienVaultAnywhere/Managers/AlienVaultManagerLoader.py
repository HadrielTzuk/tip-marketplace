from AlienVaultAnywhereManagerV1 import AlienVaultAnywhereManagerV1
from AlienVaultAnywhereManagerV2 import AlienVaultAnywhereManagerV2
from enum import Enum


class ManagerVersionNotFound(Exception):
    pass


class ManagerVersionsEnum(Enum):
    V1 = 1
    V2 = 2


class AlienVaultManagerLoader(object):
    @staticmethod
    def load_manager(version, *args, **kwargs):
        """
        Load the relevant manager based on integration parameter
        :param version: {string} V1/V2
        :return: {manager instance) the relevant manager instance
        """
        if version == ManagerVersionsEnum.V1.name:
            return AlienVaultAnywhereManagerV1(*args, **kwargs)

        elif version == ManagerVersionsEnum.V2.name:
            return AlienVaultAnywhereManagerV2(*args, **kwargs)

        raise ManagerVersionNotFound("Manager version {} was not found. Aborting.".format(version))
