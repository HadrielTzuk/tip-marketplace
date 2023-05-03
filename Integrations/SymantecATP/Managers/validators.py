from constants import (
    PRIORITIES
)
from TIPCommon import convert_list_to_comma_string


class SymantecATPValidatorException(Exception):
    pass


class SymantecATPValidator(object):
    @staticmethod
    def validate_priorities(priorities):
        for priority in priorities:
            if not priority.upper() in PRIORITIES:
                raise SymantecATPValidatorException(
                    u'{} not in {}'
                    .format(priority, convert_list_to_comma_string(PRIORITIES))
                )