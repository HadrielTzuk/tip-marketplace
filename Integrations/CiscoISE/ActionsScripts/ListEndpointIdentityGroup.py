from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CiscoISEManager import CiscoISEManager, FILTER_KEY_MAPPING, FILTER_STRATEGY_MAPPING
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import construct_csv


INTEGRATION_NAME = u"CiscoISE"
PRODUCT_NAME = u"Cisco ISE"
SCRIPT_NAME = u"Cisco ISE - List Endpoint Identity Group"
TABLE_NAME = "Available Endpoint Entity Groups"
MAX_LIMIT = 100


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           print_value=True, is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           print_value=True, is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             input_type=bool, print_value=True, is_mandatory=True)

    # Action parameters
    filter_key = extract_action_param(siemplify, param_name=u"Filter Key", print_value=True)
    filter_logic = extract_action_param(siemplify, param_name=u"Filter Logic", print_value=True)
    filter_value = extract_action_param(siemplify, param_name=u"Filter Value", print_value=True)
    limit = extract_action_param(siemplify, param_name=u"Max Records To Return", input_type=int,
                                 default_value=MAX_LIMIT, print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED

    try:
        if not FILTER_KEY_MAPPING.get(filter_key) and FILTER_STRATEGY_MAPPING.get(filter_logic):
            raise Exception(u"you need to select a field from the \"Filter Key\" parameter")

        if limit <= 0:
            raise Exception(u"Invalid value was provided for \"Max Records to Return\": {}. "
                            u"Positive number should be provided".format(limit))

        if limit > 100:
            raise Exception(u"Invalid value was provided for \"Max Records to Return\". "
                            u"Maximum number can be provided is {}".format(MAX_LIMIT))

        manager = CiscoISEManager(api_root=api_root, username=username, password=password, verify_requests=verify_ssl,
                                  logger=siemplify.LOGGER)

        groups = manager.get_endpoint_groups(FILTER_KEY_MAPPING.get(filter_key),
                                             FILTER_STRATEGY_MAPPING.get(filter_logic),
                                             filter_value, limit)

        if groups:
            siemplify.result.add_data_table(TABLE_NAME, construct_csv([group.to_csv() for group in groups]))
            siemplify.result.add_result_json([group.to_json() for group in groups])
            output_message = u"Successfully found endpoint entity groups for the provided criteria " \
                             u"in {}.".format(PRODUCT_NAME)
        else:
            result = False
            output_message = u"No endpoint entity groups were found for the provided criteria " \
                             u"in {}.".format(PRODUCT_NAME)

        if FILTER_KEY_MAPPING.get(filter_key) and FILTER_STRATEGY_MAPPING.get(filter_logic) and not filter_value:
            output_message += "\nThe filter was not applied, because parameter \"Filter Value\" has an empty value."

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = u"Error executing action \"{}\". Reason: {}".format(SCRIPT_NAME, e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
