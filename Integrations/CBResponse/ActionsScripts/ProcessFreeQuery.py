from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, add_prefix_to_dict
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from CBResponseManagerLoader import CBResponseManagerLoader
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

# =====================================
#             CONSTANTS               #
# =====================================
INTEGRATION_NAME = u"CBResponse"
SCRIPT_NAME = u"CBResponse - Process Free Query"
ENTITY_TABLE_HEADER = u"Processes"


@output_handler
def main():
    siemplify = SiemplifyAction()
    status = EXECUTION_STATE_COMPLETED
    result_value = u"true"
    siemplify.script_name = SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           input_type=unicode)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key",
                                          input_type=unicode)
    version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Version",
                                          input_type=float)

    # INIT ACTION PARAMETERS:
    query = extract_action_param(siemplify, param_name="Query", is_mandatory=True, print_value=True, input_type=unicode)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        # If no exception occur - then connection is successful
        manager = CBResponseManagerLoader.load_manager(version, api_root, api_key, siemplify.LOGGER)
        processes = manager.process_free_query(query)

        if processes:
            siemplify.result.add_entity_table(ENTITY_TABLE_HEADER,
                                              construct_csv([process.to_csv() for process in processes]))
            siemplify.result.add_result_json([process.to_json() for process in processes])

            output_message = u"Found {} processes.".format(len(processes))
        else:
            output_message = u"No processes were found."

        siemplify.LOGGER.info(u"Finished processing")
    except Exception, e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Some errors occurred. Please check log"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
