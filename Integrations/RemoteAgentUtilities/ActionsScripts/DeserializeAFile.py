from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_action_param
import os
import base64

INTEGRATION_NAME = u"RemoteAgentUtilities"
SCRIPT_NAME = u"Deserialize A File"
AGENT_FOLDER = u"/opt/SiemplifyAgent/Files/"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    file_content = extract_action_param(siemplify, param_name=u"File base64", is_mandatory=True, input_type=unicode,
                                      print_value=False)
    file_name = extract_action_param(siemplify, param_name=u"File Name", is_mandatory=True, input_type=unicode,
                                      print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    json_results = {}
    status = EXECUTION_STATE_COMPLETED

    try:
        if not os.path.exists(AGENT_FOLDER):
            siemplify.LOGGER.info(u"Creating folder {}".format(AGENT_FOLDER))
            os.makedirs(AGENT_FOLDER)

        new_file_path = os.path.join(AGENT_FOLDER, file_name)

        with open(new_file_path, 'wb') as f:
            siemplify.LOGGER.info(u"Writing file content to {}".format(new_file_path))
            f.write(base64.b64decode(file_content))
            output_message = u'Successfully deserialized file base 64. New file is available here: {}'.format(new_file_path)
            result_value = new_file_path

    except Exception as e:
        siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u""
        output_message = u"Action didn't complete due to error: {}".format(e)

    siemplify.result.add_result_json(json_results)
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
