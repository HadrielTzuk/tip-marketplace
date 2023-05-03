from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from CBResponseManagerLoader import CBResponseManagerLoader
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

# =====================================
#             CONSTANTS               #
# =====================================
INTEGRATION_NAME = u"CBResponse"
SCRIPT_NAME = u"CBResponse - Get FileMod Data For Process"


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

        elapsed_process = manager.get_process_filemod_list(process_id, segment_id)

        data_table = [file_mode.to_data_table() for file_mode in elapsed_process.process.file_modes]

        if data_table:
            siemplify.result.add_data_table(title=u"Report for: {}".format(process_id),
                                            data_table=construct_csv(data_table))
            output_message = u"Found filemod data for process id: {0}, segment id: {1}".format(process_id, segment_id)
        else:
            output_message = u"No filemod data found for process id: {0}, segment id: {1}".format(process_id,
                                                                                                  segment_id)

        siemplify.result.add_result_json(elapsed_process.to_json())
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
