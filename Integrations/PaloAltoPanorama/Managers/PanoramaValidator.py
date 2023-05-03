from PanoramaExceptions import (
    PanoramaSeverityException
)
from PanoramaConstants import (
    PANORAMA_TO_SIEM_SEVERITY
)
from PanoramaCommon import PanoramaCommon


class PanoramaValidator(object):
    @staticmethod
    def validate_severity(severity):
        # type: (str or unicode) -> None or PanoramaSeverityException
        """
        Validate if severity is acceptable
        @param severity: Severity. Ex. Low
        """
        acceptable_severities = [key.lower() for key in PANORAMA_TO_SIEM_SEVERITY.keys()]
        if severity not in acceptable_severities:
            raise PanoramaSeverityException(
                u'Severity \"{}\" is not in {}'
                .format(
                    severity,
                    PanoramaCommon.convert_list_to_comma_separated_string(acceptable_severities)
                )
            )
