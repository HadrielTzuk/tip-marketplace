from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from MicrosoftDefenderATPManager import MicrosoftDefenderATPManager, MicrosoftDefenderATPError, \
    MicrosoftDefenderATPValidationError

PROVIDER_NAME = u'MicrosoftDefenderATP'
SCRIPT_NAME = u'{} - List Alerts'.format(PROVIDER_NAME)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Api Root",
        input_type=unicode,
        is_mandatory=True
    )

    client_id = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Client ID",
        input_type=unicode,
        is_mandatory=True
    )

    client_secret = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Client Secret",
        input_type=unicode,
        is_mandatory=True
    )

    tenant_id = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Azure Active Directory ID",
        input_type=unicode,
        is_mandatory=True
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Verify SSL",
        input_type=bool,
        is_mandatory=True,
        default_value=False
    )

    time_frame = extract_action_param(
        siemplify,
        param_name="Time Frame",
        input_type=int,
        is_mandatory=False
    )

    statuses = extract_action_param(
        siemplify,
        param_name="Status",
        input_type=unicode,
        is_mandatory=False
    )

    severities = extract_action_param(
        siemplify,
        param_name="Severity",
        input_type=unicode,
        is_mandatory=False
    )

    categories = extract_action_param(
        siemplify,
        param_name="Category",
        input_type=unicode,
        is_mandatory=False
    )

    incident_id = extract_action_param(
        siemplify,
        param_name="Incident ID",
        input_type=int,
        is_mandatory=False
    )

    statuses = MicrosoftDefenderATPManager.convert_comma_separated_to_list(statuses)
    severities = MicrosoftDefenderATPManager.convert_comma_separated_to_list(severities)
    categories = MicrosoftDefenderATPManager.convert_comma_separated_to_list(categories)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    # Validation block
    validation_errors = []

    if statuses:
        try:
            MicrosoftDefenderATPManager.validate_statuses(*statuses)
        except MicrosoftDefenderATPValidationError as e:
            validation_errors.append(e.message)

    if severities:
        try:
            MicrosoftDefenderATPManager.validate_severities(*severities)
        except MicrosoftDefenderATPValidationError as e:
            validation_errors.append(e.message)

    if categories:
        try:
            MicrosoftDefenderATPManager.validate_categories(*categories)
        except MicrosoftDefenderATPValidationError as e:
            validation_errors.append(e.message)

    if validation_errors:
        siemplify.end(
            MicrosoftDefenderATPManager.join_validation_errors(validation_errors),
            u'false',
            EXECUTION_STATE_FAILED
        )

    try:
        microsoft_defender_atp = MicrosoftDefenderATPManager(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            resource=api_root,
            verify_ssl=verify_ssl
        )

        alerts = microsoft_defender_atp.get_alerts(
            alert_time_frame=time_frame,
            statuses=statuses,
            severities=severities,
            categories=categories,
            incident_id=incident_id
        )

        if not alerts:
            output_message = u'Action was not able to find any alerts'
        else:
            output_message = u'Successfully returned the following alerts: {}'.format([alert.id for alert in alerts])

            siemplify.result.add_result_json([alert.to_json() for alert in alerts])

            siemplify.result.add_data_table(
                title=u'Defender ATP alerts found:',
                data_table=construct_csv([alert.to_table() for alert in alerts])
            )

        result = u'true'
        status = EXECUTION_STATE_COMPLETED

    except MicrosoftDefenderATPError as e:
        output_message = u'Action didn\'t completed due to error: {}'.format(e)
        result = u'false'
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u'Status: {}'.format(status))
    siemplify.LOGGER.info(u'Result: {}'.format(result))
    siemplify.LOGGER.info(u'Output Message: {}'.format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
