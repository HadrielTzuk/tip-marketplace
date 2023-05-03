from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from Rapid7InsightIDRManager import Rapid7InsightIDRManager
from constants import PROVIDER_NAME, SET_INVESTIGATION_ASSIGNEE_SCRIPT_NAME
from Rapid7InsightIDRExceptions import NotFoundException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SET_INVESTIGATION_ASSIGNEE_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="API Key",
                                          is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Verify SSL",
                                             is_mandatory=False, input_type=bool, print_value=True)

    investigation_id = extract_action_param(siemplify, param_name="Investigation ID", is_mandatory=True,
                                            print_value=True)
    assignee_email = extract_action_param(siemplify, param_name="Assignee email", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = True
    output_message = ""
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = Rapid7InsightIDRManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl,
                                          siemplify_logger=siemplify.LOGGER)
        result = manager.set_investigation_assignee(investigation_id, assignee_email)

        if result:
            siemplify.result.add_result_json(result.to_json())
            output_message = "{} Investigation {} assignee changed to {}".format(PROVIDER_NAME, investigation_id,
                                                                                 assignee_email)

    except NotFoundException as e:
        result_value = False
        output_message = "Failed to update {} investigation assignee. Error is: {}".format(PROVIDER_NAME, e)
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(SET_INVESTIGATION_ASSIGNEE_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = "Failed to connect to the {} service! Error is {}".format(PROVIDER_NAME, e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
