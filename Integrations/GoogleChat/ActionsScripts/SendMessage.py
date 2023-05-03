from SiemplifyUtils import output_handler
from GoogleChatManager import GoogleChatManager
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import SEND_MESSAGE_SCRIPT_NAME, INTEGRATION_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SEND_MESSAGE_SCRIPT_NAME
    siemplify.LOGGER.info("================= Main - Param Init =================")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                           param_name="API Root URL", is_mandatory=True)
    service_account = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Service Account")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             print_value=True, input_type=bool)

    space_name = extract_action_param(siemplify, param_name="Space Name", is_mandatory=True, print_value=True)
    text = extract_action_param(siemplify, param_name="Message Text", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        manager = GoogleChatManager(api_root=api_root, service_account_string=service_account,
                                    verify_ssl=verify_ssl, force_check_connectivity=True)
        message = manager.create_message(space_name=space_name, message=text)
        siemplify.result.add_result_json(message.to_json())
        output_message = "Message was sent successfully."

    except Exception as e:
        siemplify.LOGGER.error(f"Error executing action \"{SEND_MESSAGE_SCRIPT_NAME}\". Reason: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action \"{SEND_MESSAGE_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
