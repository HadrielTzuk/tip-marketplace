from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from MicrosoftDefenderATPManager import MicrosoftDefenderATPManager, MicrosoftDefenderATPError, \
    MicrosoftDefenderATPValidationError

PROVIDER_NAME = u'MicrosoftDefenderATP'
SCRIPT_NAME = u'{} - List Machines'.format(PROVIDER_NAME)


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

    last_seen_time_frame = extract_action_param(
        siemplify,
        param_name="Last Seen Time Frame",
        input_type=int,
        is_mandatory=False
    )

    name = extract_action_param(
        siemplify,
        param_name="Machine Name",
        input_type=unicode,
        is_mandatory=False
    )

    ip = extract_action_param(
        siemplify,
        param_name="Machine IP Address",
        input_type=unicode,
        is_mandatory=False
    )

    risk_scores = extract_action_param(
        siemplify,
        param_name="Machine Risk Score",
        input_type=unicode,
        is_mandatory=False
    )

    health_statuses = extract_action_param(
        siemplify,
        param_name="Machine Health Status",
        input_type=unicode,
        is_mandatory=False
    )

    os_platform = extract_action_param(
        siemplify,
        param_name="Machine OS Platform",
        input_type=unicode,
        is_mandatory=False
    )

    rbac_group_id = extract_action_param(
        siemplify,
        param_name="RBAC Group ID",
        input_type=int,
        is_mandatory=False
    )

    risk_scores = MicrosoftDefenderATPManager.convert_comma_separated_to_list(risk_scores)
    health_statuses = MicrosoftDefenderATPManager.convert_comma_separated_to_list(health_statuses)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    # Validation block
    validation_errors = []

    if health_statuses:
        try:
            MicrosoftDefenderATPManager.validate_health_statuses(*health_statuses)
        except MicrosoftDefenderATPValidationError as e:
            validation_errors.append(e.message)

    if risk_scores:
        try:
            MicrosoftDefenderATPManager.validate_risk_scores(*risk_scores)
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

        machines = microsoft_defender_atp.get_machines(
            last_seen_time_frame=last_seen_time_frame,
            name=name,
            ip=ip,
            risk_scores=risk_scores,
            health_statuses=health_statuses,
            os_platform=os_platform,
            rbac_group_id=rbac_group_id
        )

        if not machines:
            output_message = u'Action was not able to find any related machines onboarded in Microsoft Defender ATP'
        else:
            output_message = u'Successfully returned machine data from Defender ATP'

            siemplify.result.add_result_json([machine.to_json() for machine in machines])

            siemplify.result.add_data_table(
                title=u'Defender ATP machines found:',
                data_table=construct_csv([machine.to_table() for machine in machines])
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
