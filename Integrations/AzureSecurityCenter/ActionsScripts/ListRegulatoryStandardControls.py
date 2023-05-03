from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from AzureSecurityCenterManager import AzureSecurityCenterManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, LIST_REGULATORY_STANDARD_CONTROLS_SCRIPT_NAME, REGULATORY_STANDARD_STATES, \
    DEFAULT_NUM_STANDARDS_TO_RETURN
from exceptions import AzureSecurityCenterValidationException
from utils import load_csv_to_list


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {LIST_REGULATORY_STANDARD_CONTROLS_SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Client ID',
        is_mandatory=True,
        print_value=True
    )

    client_secret = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Client Secret',
        is_mandatory=True,
        print_value=False
    )
    username = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Username',
        is_mandatory=False,
        print_value=True
    )

    password = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Password',
        is_mandatory=False,
        print_value=False
    )
    subscription_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Subscription ID',
        print_value=True
    )
    tenant_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Tenant ID',
        is_mandatory=True,
        print_value=True
    )
    refresh_token = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Refresh Token',
        is_mandatory=False
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Verify SSL",
        default_value=False,
        input_type=bool,
        is_mandatory=True)

    # Action parameters
    action_subscription_id = extract_action_param(siemplify, param_name="Subscription ID", print_value=True)
    standard_names = extract_action_param(siemplify, param_name="Standard Names", is_mandatory=True,
                                          print_value=True)
    state_filter = extract_action_param(siemplify, param_name="State Filter", default_value=None, is_mandatory=False,
                                        print_value=True)
    max_standards_to_return = extract_action_param(siemplify, param_name="Max Standards To Return", is_mandatory=False,
                                                   default_value=DEFAULT_NUM_STANDARDS_TO_RETURN, input_type=int,
                                                   print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED

    successful_standards = []
    missing_standards = []
    failed_standards = []

    output_message = ""
    json_results = {
        'results': []
    }
    result_value = False

    try:
        standard_names = load_csv_to_list(csv=standard_names, param_name="Standard Names")
        subscription_id = action_subscription_id or subscription_id

        if not subscription_id:
            raise Exception(
                "you need to provide subscription ID in the integration configuration or action configuration."
            )

        state_filter = load_csv_to_list(csv=state_filter, param_name="State Filter") if state_filter else []
        state_filter = [state.lower() for state in state_filter]
        for state in state_filter:
            if state not in REGULATORY_STANDARD_STATES:
                raise AzureSecurityCenterValidationException(
                    f"'State Filter' parameter should only contain the following values: {', '.join(REGULATORY_STANDARD_STATES)}")

        if max_standards_to_return < 0:
            siemplify.LOGGER.info(
                f"'Max Standards To Return' parameter is negative. Using default value of {DEFAULT_NUM_STANDARDS_TO_RETURN}")
            max_standards_to_return = DEFAULT_NUM_STANDARDS_TO_RETURN

        manager = AzureSecurityCenterManager(client_id=client_id, client_secret=client_secret, username=username,
                                             password=password, subscription_id=subscription_id,
                                             tenant_id=tenant_id, refresh_token=refresh_token, verify_ssl=verify_ssl)

        manager.get_regulatory_compliance_standards(subscription_id=subscription_id)

        for standard_name in standard_names:
            try:
                regulatory_standards = manager.get_regulatory_standard_controls(state_filters=state_filter,
                                                                                standard_name=standard_name,
                                                                                limit=max_standards_to_return)
                if regulatory_standards:
                    successful_standards.extend(regulatory_standards)
                    json_results['results'].append({
                        'Name': standard_name,
                        'Controls': [regulatory_standard.as_json() for regulatory_standard in regulatory_standards]
                    })
                else:
                    missing_standards.append(standard_name)
                    siemplify.LOGGER.info(
                        f"Didn't find regulatory standards for standard name {standard_name}")

            except Exception as e:
                siemplify.LOGGER.error(f"Unable to get standard controls for standard name {standard_name}")
                siemplify.LOGGER.exception(e)
                failed_standards.append(standard_name)

        if successful_standards:
            output_message += "Successfully retrieved regulatory controls for the following standards in Microsoft {}:\n    {}\n\n".format(
                INTEGRATION_NAME, ', '.join({standard.standard_name for standard in successful_standards})
            )
            siemplify.result.add_data_table("Regulatory Controls",
                                            construct_csv([reg.as_csv() for reg in successful_standards]))
            result_value = True

        if failed_standards:
            output_message += "Action wasn't able to retrieve regulatory controls for the following standards in Microsoft {}:\n     {}\n\n".format(
                INTEGRATION_NAME, ', '.join(failed_standards)
            )
            result_value = True

        if missing_standards:
            output_message += "No regulatory controls were found for the following standards in Microsoft {}:\n     {}\n\n".format(
                INTEGRATION_NAME, ', '.join(missing_standards)
            )
            result_value = True

        if not successful_standards and not missing_standards:
            output_message += "No regulatory controls were found for the provided standards."
            result_value = False

    except Exception as e:
        siemplify.LOGGER.error(
            f"Error executing action \"{LIST_REGULATORY_STANDARD_CONTROLS_SCRIPT_NAME}\". Reason: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{LIST_REGULATORY_STANDARD_CONTROLS_SCRIPT_NAME}\". Reason: {e}"

    try:
        siemplify.result.add_result_json(json_results)
    except Exception as e:
        siemplify.LOGGER.error(e)
        siemplify.LOGGER.exception(e)
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
