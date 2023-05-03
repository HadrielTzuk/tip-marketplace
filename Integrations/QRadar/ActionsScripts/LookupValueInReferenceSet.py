from SiemplifyUtils import output_handler
from TIPCommon import extract_action_param, extract_configuration_param
from SiemplifyAction import SiemplifyAction
from QRadarManager import QRadarManager
from exceptions import QRadarNotFoundError
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    LOOKUP_VALUE_IN_REFERENCE_SET_SCRIPT_NAME
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LOOKUP_VALUE_IN_REFERENCE_SET_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    api_version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Version')

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    name = extract_action_param(siemplify, param_name='Name', is_mandatory=True, print_value=True)
    value = extract_action_param(siemplify, param_name='Value', is_mandatory=True, print_value=True)

    status = EXECUTION_STATE_COMPLETED
    result_value = False

    try:
        manager = QRadarManager(api_root, api_token, api_version)
        reference_set = manager.lookup_for_value_in_reference_set(name, value)
        if reference_set and reference_set.data:
            siemplify.result.add_result_json(reference_set.data)
            result_value = True
            output_message = f"Found {value} in the reference set."
        else:
            output_message = f"Could not find {value} in the reference set."

    except QRadarNotFoundError as e:
        output_message = f"Failed to lookup {value} in the reference set."
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    except Exception as e:
        output_message = f'Error executing {LOOKUP_VALUE_IN_REFERENCE_SET_SCRIPT_NAME}. Reason {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
