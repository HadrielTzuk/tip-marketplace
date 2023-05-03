from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from constants import INTEGRATION_NAME, CREATE_CASE_SCRIPT_NAME
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from LogRhythmManager import LogRhythmRESTManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_CASE_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                          is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    name = extract_action_param(siemplify, param_name="Name", is_mandatory=True, print_value=True)
    priority = extract_action_param(siemplify, param_name="Priority", is_mandatory=True, default_value=1,
                                    input_type=int, print_value=True)
    due_date = extract_action_param(siemplify, param_name="Due Date", print_value=True)
    description = extract_action_param(siemplify, param_name="Description", print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        manager = LogRhythmRESTManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl,
                                       force_check_connectivity=True)

        case = manager.create_case(name=name, priority=priority, due_date=due_date, description=description)
        output_message = f'Successfully created case {case.number} in {INTEGRATION_NAME}.'
        siemplify.result.add_result_json(case.as_json())

    except Exception as e:
        output_message = f"Error executing action {CREATE_CASE_SCRIPT_NAME}. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
