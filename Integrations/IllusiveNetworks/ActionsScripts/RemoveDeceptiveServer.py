from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from IllusiveNetworksManager import IllusiveNetworksManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from IllusiveNetworksExceptions import ManagerNotFoundException
from constants import (
    INTEGRATION_NAME,
    PRODUCT_NAME,
    REMOVE_DECEPTIVE_SERVER_SCRIPT_NAME
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = REMOVE_DECEPTIVE_SERVER_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Key',
                                          is_mandatory=True, print_value=False)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name='CA Certificate File')
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool, is_mandatory=True)

    server_name = extract_action_param(siemplify, param_name='Server Name', is_mandatory=True, print_value=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    status = EXECUTION_STATE_COMPLETED
    result_value = False

    try:
        manager = IllusiveNetworksManager(api_root=api_root, api_key=api_key, ca_certificate=ca_certificate,
                                          verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)

        deceptive_server = manager.get_deceptive_server_or_raise(server_name)

        manager.remove_deceptive_server([deceptive_server.domain])
        result_value = True
        output_message = f'Successfully removed deceptive server in {PRODUCT_NAME}.'

    except ManagerNotFoundException as e:
        output_message = f"Action wasn't able to remove deceptive server \"{server_name}\". Reason: {e}"
    except Exception as e:
        output_message = f"Error executing action '{REMOVE_DECEPTIVE_SERVER_SCRIPT_NAME}'. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
