from ObserveITExceptions import (
    ObserveITSeverityException
)
from ObserveITConstants import (
    OBSERVE_IT_TO_SIEM_SEVERITY
)
from ObserveITCommon import ObserveITCommon


class ObserveITValidator(object):
    @staticmethod
    def validate_severity(severity):
        # type: (str or unicode) -> None or ObserveITSeverityException
        """
        Validate if severity is acceptable
        @param severity: Severity. Ex. Low
        """
        acceptable_severities = OBSERVE_IT_TO_SIEM_SEVERITY.keys()
        if severity not in acceptable_severities:
            raise ObserveITSeverityException(
                u'Severity \"{}\" is not in {}'
                .format(
                    severity,
                    ObserveITCommon.convert_list_to_comma_separated_string(acceptable_severities)
                )
            )
