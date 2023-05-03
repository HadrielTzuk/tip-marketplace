from SiemplifyUtils import output_handler
from FireEyeEXManager import FireEyeEXManager, FireEyeEXUnsuccessfulOperationError
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param


INTEGRATION_NAME = u"FireEyeEX"
SCRIPT_NAME = u"Delete Quarantined Email"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                          is_mandatory=True, input_type=unicode)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                         is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    queue_id = extract_action_param(siemplify, param_name=u"Queue ID", is_mandatory=True,
                                    input_type=unicode, print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED

    try:
        ex_manager = FireEyeEXManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl)
        ex_manager.delete_quarantined_email(queue_id)
        output_message = u"Successfully deleted FireEye EX quarantined email with queue id {}!".format(queue_id)
        result_value = u"true"

        ex_manager.logout()

    except FireEyeEXUnsuccessfulOperationError as e:
        siemplify.LOGGER.error(u"Email with queue id {} was not deleted.".format(queue_id))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message = u"Email with queue id {} was not deleted. Reason: {}".format(queue_id, e)
        result_value = u"false"

    except Exception as e:
        siemplify.LOGGER.error(u"Error executing action \"Delete Quarantined Email\". Reason: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Error executing action \"Delete Quarantined Email\". Reason: {}".format(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == u"__main__":
    main()
