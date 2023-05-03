from SiemplifyUtils import output_handler
from TIPCommon import extract_action_param, extract_configuration_param
from SiemplifyAction import SiemplifyAction
from QRadarManager import QRadarManager
from exceptions import QRadarNotFoundError, QRadarValidationError
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    UPDATE_OFFENSE_SCRIPT_NAME,
    CLOSED_STATUS,
    DO_NOT_CHANGE_STATUS
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_OFFENSE_SCRIPT_NAME

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
        assigned_to = extract_action_param(siemplify, param_name='Assigned To', is_mandatory=False, print_value=True)

        offense_status = extract_action_param(siemplify, param_name='Status', is_mandatory=True, print_value=True)
        offense_status = "" if offense_status == DO_NOT_CHANGE_STATUS else offense_status

        closing_reason = extract_action_param(siemplify, param_name='Closing Reason', is_mandatory=False,
                                              print_value=True)
        follow_up = extract_action_param(siemplify, param_name='Follow Up', input_type=bool, is_mandatory=False,
                                         print_value=True)

        protected = extract_action_param(siemplify, param_name='Protected', input_type=bool, is_mandatory=False,
                                         print_value=True)

        manager = QRadarManager(api_root, api_token, api_version)
        closing_reason_id = manager.get_closing_reason_id(reason_name=closing_reason) if \
            offense_status == CLOSED_STATUS else None
        updated_offense = manager.update_offense(offense_id=offense_id, closing_reason_id=closing_reason_id,
                                                 status=offense_status, assigned_to=assigned_to, follow_up=follow_up,
                                                 protected=protected)
        siemplify.result.add_result_json(updated_offense.to_json())
        result_value = True
        output_message = f"Offense {offense_id} was updated."

    except QRadarValidationError as e:
        output_message = f"Action wasn't able to update offense with ID: {offense_id}. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    except QRadarNotFoundError as e:
        output_message = f'Error executing {UPDATE_OFFENSE_SCRIPT_NAME}. Reason: offense with ID {offense_id} ' \
                         f'wasn\'t found in {INTEGRATION_NAME}. Please check the spelling.'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    except Exception as e:
        output_message = f'Error executing {UPDATE_OFFENSE_SCRIPT_NAME}. Reason: {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
