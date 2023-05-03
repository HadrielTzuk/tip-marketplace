from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from TaniumManager import TaniumManager
from constants import INTEGRATION_NAME, CREATE_QUESTION_SCRIPT_NAME
from exceptions import TaniumBadRequestException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_QUESTION_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True, print_value=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True, remove_whitespaces=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             input_type=bool, print_value=True)
    question = extract_action_param(siemplify, param_name='Question Text', print_value=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    output_message = ""
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        manager = TaniumManager(api_root=api_root, api_token=api_token, verify_ssl=verify_ssl,
                                force_check_connectivity=True, logger=siemplify.LOGGER)

        question = manager.create_question(question=question)
        output_message = f"Successfully created Tanium question with id {question.id}"
        siemplify.result.add_result_json(question.to_json())

    except Exception as err:
        output_message = f"Error executing action {CREATE_QUESTION_SCRIPT_NAME}. Reason: {err}"
        if isinstance(err, TaniumBadRequestException):
            output_message = f"Error executing action {CREATE_QUESTION_SCRIPT_NAME} because provided question " \
                             "text is invalid. "
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
