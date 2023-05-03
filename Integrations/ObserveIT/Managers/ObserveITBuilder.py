import re

from ObserveITDatamodels import (
    Alert
)


class ObserveITBuilder(object):
    def build_alert(self, alert_data):
        # type: (dict) -> Alert
        """
        Build alert from response dict
        @param alert_data: Response dict
        @return: Alert
        """
        return Alert(raw_data=alert_data, **self._change_param_names(alert_data))

    def _change_param_names(self, data):
        # type: (dict) -> dict
        """
        Convert all camel keys in dict to snake one
        @param data: dictionary with camel case keys
        @return: dictionary with snake case keys
        """
        return {self._covert_camel_to_snake(key): value for key, value in data.items()}

    @staticmethod
    def _covert_camel_to_snake(camel):
        # type: (str or unicode) -> str or unicode
        """
        Converts camel case to snake
        @param camel: Camel case string
        @return: Snake case string
        """
        camel = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', camel)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', camel).lower().replace('__', '_')
