from SiemplifyUtils import output_handler
from FireEyeEXManager import FireEyeEXManager
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

INTEGRATION_NAME = u"FireEyeEX"
SCRIPT_NAME = u"List quarantined emails"


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

    start_time = extract_action_param(siemplify, param_name=u"Start Time", is_mandatory=False,
                                    input_type=unicode, print_value=True)
    end_time = extract_action_param(siemplify, param_name=u"End Time", is_mandatory=False,
                                       input_type=unicode, print_value=True)
    sender = extract_action_param(siemplify, param_name=u"Sender Filter", is_mandatory=False,
                                 input_type=unicode, print_value=True)
    subject = extract_action_param(siemplify, param_name=u"Subject Filter", is_mandatory=False,
                                      input_type=unicode, print_value=True)
    limit = extract_action_param(siemplify, param_name=u"Max Email to Return", is_mandatory=False,
                                         input_type=int, print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    json_results = []
    status = EXECUTION_STATE_COMPLETED
    result_value = u"true"

    try:
        ex_manager = FireEyeEXManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl)
        quarantined_emails = ex_manager.list_quarantined_emails(
            start_time=start_time,
            end_time=end_time,
            sender=sender,
            subject=subject,
            limit=limit
        )

        json_results = [email.raw_data for email in quarantined_emails]

        siemplify.LOGGER.info(u"Found {} quarantined emails.".format(len(quarantined_emails)))

        if quarantined_emails:
            siemplify.result.add_data_table(u"Quarantined Emails",
                                            construct_csv([email.as_csv() for email in quarantined_emails]))
            output_message = u"Successfully listed FireEye EX quarantined emails!"

        else:
            output_message = u"No quarantined emails were found in FireEye EX!"

        ex_manager.logout()

    except Exception as e:
        siemplify.LOGGER.error(u"Error executing action \"List Quarantined Emails\". Reason: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Error executing action \"List Quarantined Emails\". Reason: {}".format(e)

    siemplify.result.add_result_json(json_results)
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == u"__main__":
    main()
