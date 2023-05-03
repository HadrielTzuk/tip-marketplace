from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_action_param
import os
import base64

INTEGRATION_NAME = u"RemoteAgentUtilities"
SCRIPT_NAME = u"Serialize A File"
MAX_FILE_SIZE = 5 * 1024 * 1024  # 10MB


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    file_path = extract_action_param(siemplify, param_name=u"File Path", is_mandatory=True, input_type=unicode,
                                      print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    json_results = {}
    result_value = u"true"
    status = EXECUTION_STATE_COMPLETED

    try:
        if not os.path.exists(file_path):
            output_message = u"{} doesn't exist or is not accessible.".format(file_path)
            siemplify.LOGGER.error(output_message)
            siemplify.end(output_message, u'false', EXECUTION_STATE_FAILED)

        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            output_message = u"{} is bigger than {}MB.".format(file_path, MAX_FILE_SIZE / (1024 * 1024))
            siemplify.LOGGER.error(output_message)
            siemplify.end(output_message, u'false', EXECUTION_STATE_FAILED)

        file_name = os.path.basename(file_path)

        with open(file_path, 'rb') as f:
            siemplify.LOGGER.info(u"Reading content from {}".format(file_path))
            file_content = f.read()

            json_results = {
                u'base64_file_content': base64.b64encode(file_content),
                u'file_name': file_name
            }
            output_message = u'Successfully serialized {}'.format(file_path)

    except Exception as e:
        siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Action didn't complete due to error: {}".format(e)

    siemplify.result.add_result_json(json_results)
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
