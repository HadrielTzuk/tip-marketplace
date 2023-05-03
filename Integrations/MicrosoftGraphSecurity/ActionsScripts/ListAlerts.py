from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from MicrosoftGraphSecurityManager import MicrosoftGraphSecurityManager
from TIPCommon import extract_configuration_param, construct_csv, extract_action_param
from exceptions import ActionParameterValidationError
import json


INTEGRATION_NAME = "MicrosoftGraphSecurity"
SCRIPT_NAME = "List Alerts"
DEFAULT_API_PAGINATION_LIMIT = 200


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, input_type=str)
    secret_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Secret ID",
                                            is_mandatory=False, input_type=str)
    certificate_path = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                   param_name="Certificate Path", is_mandatory=False, input_type=str)
    certificate_password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                       param_name="Certificate Password", is_mandatory=False,
                                                       input_type=str)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Tenant",
                                         is_mandatory=True, input_type=str)

    filter_key = extract_action_param(siemplify, param_name='Filter Key', is_mandatory=True,
                                      input_type=str, print_value=True)
    filter_logic = extract_action_param(siemplify, param_name='Filter Logic', is_mandatory=True,
                                        input_type=str, print_value=True)
    filter_value = extract_action_param(siemplify, param_name='Filter Value', is_mandatory=False,
                                        input_type=str, print_value=True)
    max_records_to_return = extract_action_param(siemplify, param_name='Max Records To Return', is_mandatory=False,
                                                 input_type=int, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    json_results = {}
    result_value = json.dumps([])

    filter_dict = None
    if max_records_to_return is None:
        max_records_to_return = DEFAULT_API_PAGINATION_LIMIT

    try:
        if max_records_to_return <= 0:
            raise ActionParameterValidationError(f'Invalid value was provided for “Max Records to Return”'
                                                 f':{max_records_to_return}. Positive number should be provided”.')

        if filter_value:
            filter_dict = {
                'key': filter_key if filter_key != 'Not Specified' else None,
                'logic': filter_logic if filter_logic != 'Not Specified' else None,
                'value': filter_value
            }
            filter_params_invalid = any(filter_dict.values()) and not all(filter_dict.values())
            if filter_params_invalid:
                raise ActionParameterValidationError('you need to select a field from '
                                                     'both the “Filter Key” and the "Filter Logic" parameter.')

        siemplify.LOGGER.info("Connecting to Microsoft Graph Security.")
        mtm = MicrosoftGraphSecurityManager(client_id, secret_id, certificate_path, certificate_password,
                                            tenant, siemplify=siemplify)
        siemplify.LOGGER.info("Connected successfully.")

        siemplify.LOGGER.info("Fetching alerts.")
        alerts = mtm.list_alerts(filter_dict=filter_dict, max_alerts=max_records_to_return)

        if alerts:
            siemplify.LOGGER.info(f"Found {len(alerts)} alerts.")

            siemplify.LOGGER.info("Adding alerts table.")
            siemplify.result.add_data_table("Alerts", construct_csv([alert.as_csv() for alert in alerts]))

            json_results = [alert.raw_data for alert in alerts]
            output_message = f"Successfully found {len(alerts)} alerts for the provided criteria in Microsoft Graph."
            result_value = json.dumps([alert.raw_data for alert in alerts])

        else:
            siemplify.LOGGER.info("No alerts were found for the provided criteria in Microsoft Graph.")
            output_message = "No alerts were found for the provided criteria in Microsoft Graph"

        status = EXECUTION_STATE_COMPLETED

    except Exception as e:
        siemplify.LOGGER.error(f'Error executing action “List Alerts”. Reason: {e}')
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message = f'Error executing action “List Alerts”. Reason: {e}'

    siemplify.result.add_result_json(json_results)
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()

