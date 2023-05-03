from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param

from MicrosoftDefenderATPManager import MicrosoftDefenderATPManager, MicrosoftDefenderATPError, \
    MicrosoftDefenderATPValidationError

PROVIDER_NAME = u'MicrosoftDefenderATP'
SCRIPT_NAME = u'{} - Update Alert'.format(PROVIDER_NAME)


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

    alert_id = extract_action_param(
        siemplify,
        param_name="Alert ID",
        input_type=unicode,
        is_mandatory=True
    )

    status = extract_action_param(
        siemplify,
        param_name="Status",
        input_type=unicode,
        is_mandatory=False
    )

    assigned_to = extract_action_param(
        siemplify,
        param_name="Assigned To",
        input_type=unicode,
        is_mandatory=False
    )

    classification = extract_action_param(
        siemplify,
        param_name="Classification",
        input_type=unicode,
        is_mandatory=False
    )

    determination = extract_action_param(
        siemplify,
        param_name="Determination",
        input_type=unicode,
        is_mandatory=False
    )

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    # Validation block
    validation_errors = []

    if status:
        try:
            MicrosoftDefenderATPManager.validate_statuses(status)
        except MicrosoftDefenderATPValidationError as e:
            validation_errors.append(e.message)

    if classification:
        try:
            MicrosoftDefenderATPManager.validate_classifications(classification)
        except MicrosoftDefenderATPValidationError as e:
            validation_errors.append(e.message)

    if determination:
        try:
            MicrosoftDefenderATPManager.validate_determinations(determination)
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

        alert = microsoft_defender_atp.update_alert(
            alert_id=alert_id,
            status=status,
            assigned_to=assigned_to,
            classification=classification,
            determination=determination
        )

        output_message = u'Successfully updated Microsoft Defender ATP alert with alert id {}'.format(alert_id)
        result = u'true'
        status = EXECUTION_STATE_COMPLETED
        siemplify.result.add_result_json(alert.to_json())

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
