from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CrowdStrikeManager import CrowdStrikeManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import API_ROOT_DEFAULT, INTEGRATION_NAME, UPDATE_IDENTITY_PROTECTION_DETECTION_SCRIPT_NAME, \
    DETECTION_STATUS_MAPPING
from exceptions import CrowdStrikeNotFoundError


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_IDENTITY_PROTECTION_DETECTION_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    # integration configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           default_value=API_ROOT_DEFAULT, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client API ID',
                                            is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client API Secret',
                                                is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             input_type=bool, is_mandatory=True, print_value=True)

    # action parameters
    detection_id = extract_action_param(siemplify, param_name='Detection ID', is_mandatory=True, print_value=True)
    detection_status = extract_action_param(siemplify, param_name='Status', print_value=True)
    assign_to = extract_action_param(siemplify, param_name='Assign To', print_value=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        if not DETECTION_STATUS_MAPPING.get(detection_status) and not assign_to:
            raise Exception("at least one of the \"Status\" or \"Assign To\" parameters should have a value")

        manager = CrowdStrikeManager(client_id=client_id, client_secret=client_secret, use_ssl=verify_ssl,
                                     api_root=api_root)

        try:
            manager.get_alerts_details([detection_id])[0]
        except CrowdStrikeNotFoundError:
            raise Exception(f"identity protection detection with ID {detection_id} wasn't found in {INTEGRATION_NAME}. "
                            f"Please check the spelling.")

        manager.update_alert(detection_id, detection_status, assign_to)
        updated_alert = manager.get_alerts_details([detection_id])[0]
        siemplify.result.add_result_json(updated_alert.to_json())
        output_message = f"Successfully updated identity protection detection with ID {detection_id} in " \
                         f"{INTEGRATION_NAME}."

    except Exception as e:
        output_message = f"Error executing action \"{UPDATE_IDENTITY_PROTECTION_DETECTION_SCRIPT_NAME}\". Reason: {e}"
        status = EXECUTION_STATE_FAILED
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()