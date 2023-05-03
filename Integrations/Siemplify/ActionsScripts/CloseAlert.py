from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED


NEW_CASE_ID_KEY = 'new_case_id'


@output_handler
def main():
    siemplify = SiemplifyAction()

    siemplify.script_name = 'Siemplify-CloseAlert'
    root_cause = siemplify.parameters["Root Cause"]
    comment = siemplify.parameters["Comment"]
    reason = siemplify.parameters["Reason"]
    tags = siemplify.parameters.get('Tags')
    user = siemplify.parameters.get('Assign To User')
    response = siemplify.close_alert(root_cause, comment, reason)

    tags_list = tags.split(',') if tags else []

    if response:
        if response.get('is_request_valid') and not response.get('errors'):
            return_status = EXECUTION_STATE_COMPLETED
            result_value = "True"
            output_message = "The alert was closed.\nRoot Cause: %s\nComment: %s\nReason: %s" % (
                root_cause, comment, reason)
            new_case_id = response.get(NEW_CASE_ID_KEY)
            for tag in tags_list:
                siemplify.add_tag(tag, case_id=new_case_id)
            if user:
                siemplify.assign_case(user, case_id=new_case_id)
        else:
            return_status = EXECUTION_STATE_FAILED
            result_value = "False"
            output_message = "Failed to close the alert. {0}".format(', '.join(response.get('errors')))
            siemplify.LOGGER.error(output_message)
    else:
        output_message = "Failed to close the alert.ERROR: Response returned as None."
        siemplify.LOGGER.error(output_message)
        return_status = EXECUTION_STATE_FAILED
        result_value = "False"

    siemplify.end(output_message, result_value, return_status)


if __name__ == '__main__':
    main()
