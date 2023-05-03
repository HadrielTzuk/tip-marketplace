from SiemplifyUtils import output_handler
from TIPCommon import extract_action_param, extract_configuration_param
from SiemplifyAction import SiemplifyAction
from QRadarManager import QRadarManager
from exceptions import QRadarNotFoundError
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    ADD_OFFENSE_NOTE_SCRIPT_NAME
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_OFFENSE_NOTE_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    api_version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Version')

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    offense_id = 0
    status = EXECUTION_STATE_COMPLETED
    result_value = False

    try:
        offense_id = extract_action_param(siemplify, param_name='Offense ID', input_type=int, is_mandatory=True,
                                          print_value=True)
        note_text = extract_action_param(siemplify, param_name='Note Text', is_mandatory=True, print_value=True)

        manager = QRadarManager(api_root, api_token, api_version)
        manager.add_offense_note(offense_id, note_text)
        result_value = True
        output_message = f"Added a note to offense  {offense_id}."

    except QRadarNotFoundError as e:
        output_message = f"Failed to add a note to offense {offense_id}."
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    except Exception as e:
        output_message = f'Error executing {ADD_OFFENSE_NOTE_SCRIPT_NAME}. Reason {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
