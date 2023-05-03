from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from Rapid7InsightIDRManager import Rapid7InsightIDRManager
from constants import PROVIDER_NAME, LIST_SAVED_QUERIES_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_SAVED_QUERIES_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="API Key",
                                          is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Verify SSL",
                                             is_mandatory=False, input_type=bool, print_value=True)

    record_limit = extract_action_param(siemplify, param_name="Record limit", input_type=int, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = Rapid7InsightIDRManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl,
                                          siemplify_logger=siemplify.LOGGER)
        results = manager.list_saved_queries(record_limit)

        if results:
            siemplify.result.add_result_json([result.to_json() for result in results])
            siemplify.result.add_entity_table(
                '{} Saved Queries'.format(PROVIDER_NAME),
                construct_csv([result.to_table() for result in results])
            )
            output_message = "{} saved queries found".format(PROVIDER_NAME)
        else:
            output_message = "No saved queries were returned."
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(LIST_SAVED_QUERIES_SCRIPT_NAME))
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
