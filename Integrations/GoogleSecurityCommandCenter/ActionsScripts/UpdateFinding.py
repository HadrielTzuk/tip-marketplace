from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from GoogleSecurityCommandCenterManager import GoogleSecurityCommandCenterManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, UPDATE_FINDING_SCRIPT_NAME, MUTE_MAPPING, \
    STATE_MAPPING
from UtilsManager import convert_comma_separated_to_list, convert_list_to_comma_string
from GoogleSecurityCommandCenterExceptions import GoogleSecurityCommandCenterInvalidJsonException, \
    GoogleSecurityCommandCenterInvalidProject


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_FINDING_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    organization_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Organization ID", print_value=True)
    service_account_string = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                         param_name="User's Service Account", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    # Action parameters
    finding_name = extract_action_param(siemplify, param_name="Finding Name", is_mandatory=True, print_value=True)
    mute_status = extract_action_param(siemplify, param_name="Mute Status", print_value=True)
    state_status = extract_action_param(siemplify, param_name="State Status", print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    successful_names, failed_names, json_results = [], [], []
    finding_names = convert_comma_separated_to_list(finding_name)
    finding_details = None

    try:
        mute_status = MUTE_MAPPING.get(mute_status)
        state_status = STATE_MAPPING.get(state_status)

        if not mute_status and not state_status:
            raise Exception(" at least one of \'Mute Status\' or \'State Status\' should have a value.")

        manager = GoogleSecurityCommandCenterManager(api_root=api_root, organization_id=organization_id,
                                                     service_account_string=service_account_string,
                                                     verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)
        manager.test_connectivity()

        for name in finding_names:
            try:
                if mute_status:
                    finding_details = manager.change_mute_status(finding_name=name, mute_status=mute_status)

                if state_status:
                    finding_details = manager.change_state_status(finding_name=name, state_status=state_status)

                if finding_details:
                    successful_names.append(name)
                    json_results.append(finding_details.as_json())
                else:
                    failed_names.append(name)
            except Exception as e:
                siemplify.LOGGER.error(f"Failed processing finding: {name}: Error is: {e}")
                failed_names.append(name)

        if successful_names:
            output_message = f"Successfully updated the following findings in " \
                             f"{INTEGRATION_DISPLAY_NAME}: {convert_list_to_comma_string(successful_names)}\n\n"
            siemplify.result.add_result_json(json_results)

        if failed_names:
            output_message += f"Action wasn't able to find the following findings in " \
                              f"{INTEGRATION_DISPLAY_NAME}: {convert_list_to_comma_string(failed_names)}\n"

        if not successful_names:
            result = False
            output_message = f"None of the provided findings were found in {INTEGRATION_DISPLAY_NAME}"

    except GoogleSecurityCommandCenterInvalidProject:
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = "Project_id was not found in JSON payload provided in the parameter " \
                         "\"User's Service Account\". Please check."
    except GoogleSecurityCommandCenterInvalidJsonException:
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = "Invalid JSON payload provided in the parameter \"User's Service Account\". Please " \
                         "check the structure."
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {UPDATE_FINDING_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{UPDATE_FINDING_SCRIPT_NAME}.\" Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result: {result}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
