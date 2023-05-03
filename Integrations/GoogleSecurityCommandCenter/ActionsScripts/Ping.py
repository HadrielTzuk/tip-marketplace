from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param
from GoogleSecurityCommandCenterManager import GoogleSecurityCommandCenterManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, PING_SCRIPT_NAME
from GoogleSecurityCommandCenterExceptions import GoogleSecurityCommandCenterInvalidJsonException, \
    GoogleSecurityCommandCenterInvalidProject


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    organization_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Organization ID", print_value=True)
    service_account_string = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                         param_name="User's Service Account", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result = False
    status = EXECUTION_STATE_FAILED

    try:
        manager = GoogleSecurityCommandCenterManager(api_root=api_root, organization_id=organization_id,
                                                     service_account_string=service_account_string,
                                                     verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)
        manager.test_connectivity()
        result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully connected to the {INTEGRATION_DISPLAY_NAME} server with the provided " \
                         f"connection parameters!"

    except GoogleSecurityCommandCenterInvalidProject:
        output_message = "Project_id was not found in JSON payload provided in the parameter " \
                         "\"User's Service Account\". Please check."
    except GoogleSecurityCommandCenterInvalidJsonException:
        output_message = "Invalid JSON payload provided in the parameter \"User's Service Account\". Please " \
                         "check the structure."
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {PING_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        output_message = f"Failed to connect to the {INTEGRATION_DISPLAY_NAME} server! Error is {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
