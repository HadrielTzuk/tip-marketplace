from SiemplifyUtils import output_handler
from FireEyeHXManager import FireEyeHXManager
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

INTEGRATION_NAME = u"FireEyeHX"
SCRIPT_NAME = u"Get Indicators"


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

    category = extract_action_param(siemplify, param_name=u"Indicator Category", is_mandatory=False,
                                    input_type=unicode, print_value=True)
    search_term = extract_action_param(siemplify, param_name=u"Search Term", is_mandatory=False,
                                       input_type=unicode, print_value=True)
    limit = extract_action_param(siemplify, param_name=u"Limit", is_mandatory=False,
                                 input_type=int, print_value=True, default_value=100)
    share_mode = extract_action_param(siemplify, param_name=u"Share Mode", is_mandatory=False,
                                      input_type=unicode, print_value=True)
    sort_by_field = extract_action_param(siemplify, param_name=u"Sort By Field", is_mandatory=False,
                                         input_type=unicode, print_value=True)
    created_by = extract_action_param(siemplify, param_name=u"Created by", is_mandatory=False,
                                      input_type=unicode, print_value=True)
    is_alerted = extract_action_param(siemplify, param_name=u"Has associated alerts", is_mandatory=False,
                                      input_type=bool, print_value=True, default_value=False)

    if share_mode == u"any":
        share_mode = None

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    json_results = []
    status = EXECUTION_STATE_COMPLETED

    try:
        hx_manager = FireEyeHXManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl)
        indicators = hx_manager.get_indicators(category=category,
                                               search=search_term,
                                               limit=limit,
                                               share_mode=share_mode,
                                               sort=sort_by_field,
                                               created_by=created_by,
                                               alerted=is_alerted)

        json_results = [indicator.raw_data for indicator in indicators]

        siemplify.LOGGER.info(u"Found {} indicators.".format(len(indicators)))

        if indicators:
            siemplify.result.add_data_table(u"Indicators",
                                            construct_csv([indicator.as_csv() for indicator in indicators]))
            output_message = u"FireEye HX indicators found."
            result_value = u"true"

        else:
            output_message = u"No FireEye HX indicators found."
            result_value = u"false"

        hx_manager.logout()

    except Exception as e:
        siemplify.LOGGER.error(u"Failed to execute action! Error is {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Failed to execute action! Error is {}".format(e)

    siemplify.result.add_result_json(json_results)
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
