from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CBResponseManagerLoader import CBResponseManagerLoader
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param

# =====================================
#             CONSTANTS               #
# =====================================
INTEGRATION_NAME = u"CBResponse"
SCRIPT_NAME = u"CBResponse - Get Process Tree Data"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    result_value = u"true"
    status = EXECUTION_STATE_COMPLETED

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           input_type=unicode)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key",
                                          input_type=unicode)
    version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Version",
                                          input_type=float)

    # INIT ACTION PARAMETERS:
    process_id = extract_action_param(siemplify, param_name="Process ID", is_mandatory=True,
                                      print_value=True, input_type=unicode)
    segment_id = extract_action_param(siemplify, param_name="Segment Id", is_mandatory=True,
                                      print_value=True, input_type=unicode)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        # If no exception occur - then connection is successful
        manager = CBResponseManagerLoader.load_manager(version, api_root, api_key, siemplify.LOGGER)

        process = manager.get_process_with_tree(process_id, segment_id)

        siemplify.result.add_result_json(process.to_json())
        siemplify.result.add_json(process_id, process.to_json())
        output_message = u"Found process tree data for process id: {}, segment id: {}".format(process_id, segment_id)

    except Exception as e:
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
