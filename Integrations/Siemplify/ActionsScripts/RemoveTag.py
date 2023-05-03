from SiemplifyUtils import output_handler
from SiemplifyAction import *
from consts import REMOVE_TAG_SCRIPT_NAME
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_action_param
import requests

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = REMOVE_TAG_SCRIPT_NAME
    tag = extract_action_param(siemplify, param_name="Tag", is_mandatory=True, print_value=True, input_type=unicode)

    try:
        tags = [t.strip() for t in tag.split(',')]

        current_case_id = siemplify.case_id
        current_alert_id = siemplify.current_alert.identifier
      
        siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
        successfully_removed_tags =[]
        failed_removed_tags = []
        output_message = u""
        status = EXECUTION_STATE_COMPLETED
        result_value = True
        
        for tag in tags:
                
            try:    
                request_dict = {u"case_id": current_case_id,
                                u"alert_identifier": current_alert_id,
                                u"tag": tag}
                address = u"{}/{}".format(siemplify.API_ROOT, u"external/v1/cases/RemoveCaseTag?format=snake")
                response = siemplify.session.post(address, json=request_dict)
                siemplify.validate_siemplify_error(response)
                successfully_removed_tags.append(tag)

            except Exception as e:
                failed_removed_tags.append(tag)
                siemplify.LOGGER.exception(e)
                
    except Exception as e:
        output_message += u'Error executing action {}. Reason: {}'.format(REMOVE_TAG_SCRIPT_NAME, e)       
        siemplify.LOGGER.error(output_message)
        status = EXECUTION_STATE_FAILED
        result_value = False

    if successfully_removed_tags:
            output_message += u"Successfully removed the following tags from case {}:{}".format(current_case_id,"\n".join([tag for tag in
                                                                                successfully_removed_tags]))
                                           
    if failed_removed_tags:
            output_message += u"Failed to remove the following tags from case {}:{}".format(current_case_id,"\n".join([tag for tag in
                                                                                failed_removed_tags]))

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        u'\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == '__main__':
	main()
