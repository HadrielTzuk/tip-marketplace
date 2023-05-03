from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MicrosoftGraphSecurityManager import MicrosoftGraphSecurityManager
from TIPCommon import extract_configuration_param, extract_action_param, flat_dict_to_csv
import json


INTEGRATION_NAME = "MicrosoftGraphSecurity"
SCRIPT_NAME = "Get Alert"


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

    alert_id = extract_action_param(siemplify, param_name='Alert ID', input_type=str, is_mandatory=True,
                                    print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    json_results = {}

    try:
        siemplify.LOGGER.info("Connecting to Microsoft Graph Security.")
        mtm = MicrosoftGraphSecurityManager(client_id, secret_id, certificate_path, certificate_password, tenant)
        siemplify.LOGGER.info("Connected successfully.")

        siemplify.LOGGER.info(f"Fetching alert {alert_id}")
        alert = mtm.get_alert_details(alert_id)

        if alert:
            siemplify.LOGGER.info(f"Found alert {alert_id} information.")
            siemplify.result.add_data_table(f"Alert {alert_id}", flat_dict_to_csv(alert.as_csv()))

            json_results = alert.raw_data
            output_message = f'Alert {alert_id} information was found.'
            result_value = json.dumps(alert.raw_data)

        else:
            siemplify.LOGGER.info(f"Alert {alert_id} information was not found.")
            output_message = f"Alert {alert_id} information was not found."
            result_value = json.dumps({})

        status = EXECUTION_STATE_COMPLETED

    except Exception as e:
        siemplify.LOGGER.error(f"Some errors occurred. Error: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = json.dumps({})
        output_message = f"Some errors occurred. Error: {e}"

    siemplify.result.add_result_json(json_results)
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()