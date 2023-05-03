from TIPCommon import convert_comma_separated_to_list, write_ids_with_timestamp

from constants import SEVERITIES


def filter_old_alerts(logger, alerts, existing_ids, id_key="entry"):
    """
    Filter alerts that were already processed
    :param logger: {SiemplifyLogger} Siemplify logger
    :param alerts: {list} List of Alert objects
    :param existing_ids: {list} List of ids to filter
    :param id_key: {str} The key of identifier
    :return: {list} List of filtered Alert objects
    """
    filtered_alerts = []

    for alert in alerts:
        id = getattr(alert, id_key)

        if id not in existing_ids.get(alert.host_id, []):
            filtered_alerts.append(alert)
        else:
            logger.info("The detection {} skipped since it has been fetched before".format(id))

    return filtered_alerts


def pass_severity_filter(siemplify, alert, lowest_severity):
    # severity filter
    if lowest_severity:
        filtered_severities = SEVERITIES[SEVERITIES.index(lowest_severity):] if lowest_severity in SEVERITIES else []
        if not filtered_severities:
            siemplify.LOGGER.info('Severity is not checked. Invalid value provided for \"Lowest Severity To Fetch\" '
                                  'parameter. Possible values are: 1, 2, 3, 4, 5.')
        if filtered_severities and alert.severity not in filtered_severities:
            siemplify.LOGGER.info('Detection with severity: {} did not pass filter. Lowest severity to fetch is '
                                  '{}.'.format(alert.severity, lowest_severity))
            return False
    return True


def pass_status_filter(siemplify, alert, status_filter):
    # status filter
    statuses = [status.capitalize() for status in convert_comma_separated_to_list(status_filter)]
    if statuses and alert.status not in statuses:
        siemplify.LOGGER.info('Detection with status: {} did not pass filter. Acceptable statuses are: {}.'.
                              format(alert.status, status_filter))
        return False
    return True


def write_ids(siemplify, ids, stored_ids_limit):
    """
    Write IDs into a ConnectorDBStream object.
    :param siemplify: {Siemplify} Siemplify object.
    :param ids: {dict} The ids to write to the file
    :param stored_ids_limit: (int) The number of recent IDs from the existing ids which will be written.
    """
    for key, value in ids.items():
        ids[key] = value[-stored_ids_limit:]

    write_ids_with_timestamp(siemplify, ids)
