# ============================= IMPORTS ===================================== #

from datamodels import Alert, Machine, User, File, Detection, QueryResult, MachineTask, SiemplifyPriorityEnum, \
    DefenderPriorityEnum, Indicator


# ============================= CLASSES ===================================== #

class MicrosoftDefenderATPTransformationLayerError(Exception):
    """
    General Exception for AzureAD DataModel TransformationLayer
    """
    pass


class MicrosoftDefenderATPTransformationLayer(object):

    @staticmethod
    def build_alert(alert_data):
        return Alert(raw_data=alert_data, **alert_data)

    @staticmethod
    def build_machine(machine_data):
        return Machine(raw_data=machine_data, **machine_data)

    @staticmethod
    def build_user(user_data):
        return User(raw_data=user_data, **user_data)

    @staticmethod
    def build_file(file_data):
        return File(raw_data=file_data, **file_data)

    @staticmethod
    def build_detection(detection_data):
        return Detection(raw_data=detection_data, **detection_data)

    @staticmethod
    def build_query_result(query_result_data):
        return QueryResult(raw_data=query_result_data, **query_result_data)

    @staticmethod
    def build_machine_task(machine_task_data):
        return MachineTask(raw_data=machine_task_data, **machine_task_data)

    @staticmethod
    def calculate_priority(alert_severity):
        """
        The function calculates case priority by the Priority Map.
        :param alert_severity: severity value as it came from Sentinel {string}
        :return: calculated Siemplify alarm priority {integer}
        """

        # UnSpecified
        if alert_severity == DefenderPriorityEnum.UNSPECIFIED.value:
            return SiemplifyPriorityEnum.UNSPECIFIED.value
        # Low.
        elif alert_severity == DefenderPriorityEnum.LOW.value:
            return SiemplifyPriorityEnum.LOW.value
        # Medium
        elif alert_severity == DefenderPriorityEnum.MEDIUM.value:
            return SiemplifyPriorityEnum.MEDIUM.value
        # High
        elif alert_severity == DefenderPriorityEnum.HIGH.value:
            return SiemplifyPriorityEnum.HIGH.value

        # Informative
        return SiemplifyPriorityEnum.INFO.value

    @staticmethod
    def get_alert_data(incident, alert_id):
        return next((alert for alert in incident.get("alerts", []) if alert.get("alertId") == alert_id), {})

    @staticmethod
    def build_indicators_list(raw_data):
        return [MicrosoftDefenderATPTransformationLayer.build_indicator(indicator_data) for indicator_data in
                raw_data.get(u"value", [])]

    @staticmethod
    def build_indicator(indicator_data):
        return Indicator(
            raw_data=indicator_data,
            identifier=indicator_data.get(u"id"),
            indicator_value=indicator_data.get(u"indicatorValue"),
            indicator_type=indicator_data.get(u"indicatorType"),
            action=indicator_data.get(u"action"),
            severity=indicator_data.get(u"severity"),
            description=indicator_data.get(u"description"),
            title=indicator_data.get(u"title"),
            recommended_actions=indicator_data.get(u"recommendedActions")
        )
