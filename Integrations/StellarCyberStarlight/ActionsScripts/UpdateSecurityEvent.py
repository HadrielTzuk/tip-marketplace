from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from StellarCyberStarlightConstants import PROVIDER_NAME, UPDATE_SECURITY_EVENT_SCRIPT_NAME, STATUS_SELECT_ONE
from TIPCommon import extract_configuration_param, extract_action_param
from StellarCyberStarlightManager import StellarCyberStarlightManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_SECURITY_EVENT_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Configurations
    api_root = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='API Root',
        is_mandatory=True,
        print_value=True
    )

    username = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='Username',
        is_mandatory=True,
        print_value=True
    )

    api_key = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='API Key',
        is_mandatory=True,
        print_value=False
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='Verify SSL',
        input_type=bool,
        is_mandatory=True,
        print_value=True
    )

    # Parameters
    index = extract_action_param(siemplify, param_name='Index', is_mandatory=True, print_value=True)
    event_id = extract_action_param(siemplify, param_name='ID', is_mandatory=True, print_value=True)
    comment = extract_action_param(siemplify, param_name='Comment', is_mandatory=False, print_value=True)
    event_status = extract_action_param(siemplify, param_name='Status', is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = False
    status = EXECUTION_STATE_COMPLETED

    try:
        
        if event_status == STATUS_SELECT_ONE and comment is None:
            raise Exception("at least one of the \"Status\", \"Comment\" should have a value.")
        
        manager = StellarCyberStarlightManager(
            api_root=api_root,
            username=username,
            api_key=api_key,
            verify_ssl=verify_ssl
        )

        manager.update_security_event(index=index, event_id=event_id, event_comment=comment, event_status=event_status)

        output_message = f"Successfully updated event {event_id} in {PROVIDER_NAME}."
        result_value = True

    except Exception as e:
        output_message = "Error executing action {}. Reason: {}".format(UPDATE_SECURITY_EVENT_SCRIPT_NAME, e)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info('Status: {}'.format(status))
    siemplify.LOGGER.info('Result: {}'.format(result_value))
    siemplify.LOGGER.info('Output Message: {}'.format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()