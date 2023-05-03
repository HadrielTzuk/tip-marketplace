from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param

from FireEyeHelixManager import FireEyeHelixManager
from FireEyeHelixConstants import (
    PROVIDER_NAME,
    PING_SCRIPT_NAME
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info('=' * 20 + ' Main - Params Init ' + '=' * 20)

    api_root = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='API Root',
        is_mandatory=True,
        print_value=True
    )

    api_token = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='API Token',
        is_mandatory=True,
        print_value=False
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='Verify SSL',
        input_type=bool,
        is_mandatory=True,
        print_value=True
    )

    siemplify.LOGGER.info('=' * 20 + ' Main - Started ' + '=' * 20)

    try:
        manager = FireEyeHelixManager(
            api_root=api_root,
            api_token=api_token,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        manager.test_connectivity()
        output_message = 'Successfully connected to the FireEye Helix server with the provided connection parameters!'
        result = True
        status = EXECUTION_STATE_COMPLETED

    except Exception as e:
        output_message = 'Failed to connect to the FireEye Helix server! Error is {}'.format(e)
        result = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('=' * 20 + ' Main - Finished ' + '=' * 20)
    siemplify.LOGGER.info('Status: {}'.format(status))
    siemplify.LOGGER.info('Result: {}'.format(result))
    siemplify.LOGGER.info('Output Message: {}'.format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
