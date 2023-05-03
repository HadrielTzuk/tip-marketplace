from consts import GLOBAL_CONTEXT, GLOBAL_CONTEXT_IDENTIFIER


def parse_version_string_to_tuple(version):
    """
    Parse version represented as string to tuple
    :param version: {str} Version represented as string. For example "5.6.1"
    :return: {tuple} Tuple of the version. For example (5,6,1)
    """
    return tuple(map(int, (version.split(u"."))))


def is_supported_siemplify_version(version, min_version):
    """
    Check if Siemplify version is supported
    :param version: {tuple} Tuple representing siemplify version. Example (5,6,1)
    :param min_version: {Tuple} Tuple representing minimum supported siemplify version. Example (5,6,0)
    :return: {bool} True if siemplify version is supported, otherwise False
    """
    return version >= min_version


def set_global_context(siemplify, key, value):
    siemplify.set_context_property(GLOBAL_CONTEXT, GLOBAL_CONTEXT_IDENTIFIER, key, value)


def get_global_context(siemplify, key):
    return siemplify.get_context_property(GLOBAL_CONTEXT, GLOBAL_CONTEXT_IDENTIFIER, key)


def send_notification(siemplify, message, notification_id):
    try:
        if hasattr(siemplify, "send_system_notification_message"):
            siemplify.send_system_notification_message(message, notification_id)
        else:
            siemplify.send_system_notification(message)
        siemplify.LOGGER.info("Notification Sent")
    except Exception as e:
        siemplify.LOGGER.error("Failed sending notification")
        siemplify.LOGGER.exception(e)
