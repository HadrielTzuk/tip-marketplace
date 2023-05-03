from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param
from GoogleAlertCenterManager import GoogleAlertCenterManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, PING_SCRIPT_NAME
from GoogleAlertCenterExceptions import GoogleAlertCenterInvalidJsonException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    service_account_json_secret = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Service Account JSON Secret",
        is_mandatory=True
    )

    impersonation_email_address = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Impersonation Email Address",
        is_mandatory=True
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Verify SSL",
        is_mandatory=True,
        input_type=bool,
        print_value=True
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result = False
    status = EXECUTION_STATE_FAILED

    try:
        manager = GoogleAlertCenterManager(
            service_account_json_secret=service_account_json_secret,
            impersonation_email_address=impersonation_email_address,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        manager.test_connectivity()
        result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully connected to the {INTEGRATION_DISPLAY_NAME} server with the provided " \
                         f"connection parameters!"

    except GoogleAlertCenterInvalidJsonException:
        output_message = "Invalid JSON payload provided in the parameter \"Service Account JSON Secret\". Please " \
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
