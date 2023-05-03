DEVICE_HOSTNAME_KEY = "hostname"
DEVICE_IP_KEY = "local_ip"


class CrowdStrikeCommon(object):
    @staticmethod
    def host_entity_output_message_pattern(entity_identifier, device_obj):
        """
        Form entity name for output message.
        :param entity_identifier: {string} Entity Identifier.
        :param device_obj: {datamodels.Device} The device obj representing the device
        :return: {string} Entity name.
        """
        return "{0}[{1}]".format(entity_identifier, device_obj.local_ip)

    @staticmethod
    def address_entity_output_message_pattern(entity_identifier, device_obj):
        """
        Form entity name for output message.
        :param entity_identifier: {string} Entity Identifier.
        :param device_obj: {datamodels.Device} The device obj representing the device
        :return: {string} Entity name.
        """
        return "{0}[{1}]".format(entity_identifier, device_obj.hostname)

    @staticmethod
    def convert_comma_separated_to_list(comma_separated):
        # type: (unicode or str) -> list
        """
        Convert comma-separated string to list
        @param comma_separated: String with comma-separated values
        @return: List of values
        """
        return [item.strip() for item in comma_separated.split(',')] if comma_separated else []

    @staticmethod
    def convert_list_to_comma_string(values_list):
        # type: (list) -> str or unicode
        """
        Convert list to comma-separated string
        @param values_list: String with comma-separated values
        @return: List of values
        """
        return ', '.join(values_list) if values_list and isinstance(values_list, list) else values_list