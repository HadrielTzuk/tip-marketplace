from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from IllusiveNetworksManager import IllusiveNetworksManager
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    PING_ACTION,
    PRODUCT_NAME
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Root", is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Key", is_mandatory=True, print_value=False)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="CA Certificate File", is_mandatory=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""
    
    try:
        illusivenetworks_manager = IllusiveNetworksManager(api_root=api_root, api_key=api_key, ca_certificate=ca_certificate, verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)
        illusivenetworks_manager.test_connectivity()
        output_message += "Successfully connected to the {} server with the provided connection parameters!".format(INTEGRATION_NAME)
        
    except Exception as e:
        output_message += 'Failed to connect to the {}! Error is {}.'.format(PRODUCT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
