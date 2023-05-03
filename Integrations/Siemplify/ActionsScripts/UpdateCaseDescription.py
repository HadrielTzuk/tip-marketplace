from SiemplifyUtils import output_handler
from SiemplifyAction import *
from consts import UPDATE_CASE_DESC_SCRIPT_NAME
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_action_param
import requests

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_CASE_DESC_SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Params Init -----------------")
    description = extract_action_param(siemplify, param_name="Description", is_mandatory=True, print_value=True, input_type=unicode)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    output_message = u""
    status = EXECUTION_STATE_COMPLETED
    result_value = True    
    
    try:
        current_case_id = siemplify.case_id
        request_dict = {u"case_id": current_case_id,
                        u"description": description}
        address = u"{}/{}".format(siemplify.API_ROOT, u"external/v1/cases/ChangeCaseDescription?format=snake")
        response = siemplify.session.post(address, json=request_dict)
        siemplify.validate_siemplify_error(response)
        output_message = u"Successfully updated case description." 

    except Exception as e:
        output_message += u'Error executing action {}. Reason: {}'.format(UPDATE_CASE_DESC_SCRIPT_NAME, e)       
        siemplify.LOGGER.error(output_message)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        u'\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == '__main__':
	main()
