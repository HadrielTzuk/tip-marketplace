from CheckpointManager import CheckpointManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param
from constants import PING_SCRIPT_NAME, INTEGRATION_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    # INIT INTEGRATION CONFIGURATION:
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Server Address",
                                                 is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    domain_name = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Domain",
                                              is_mandatory=False, default_value="")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    connectivity_result = True
    output_message = "Connection Established."
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = CheckpointManager(server_address=server_address, username=username, password=password,
                                    domain=domain_name, verify_ssl=verify_ssl)
        manager.test_connectivity()
        manager.discard()
        manager.log_out()
    except Exception as err:
        output_message = 'Connection Failed. Error is {}'.format(err)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)
        status = EXECUTION_STATE_FAILED
        connectivity_result = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, connectivity_result, output_message))
    siemplify.end(output_message, connectivity_result, status)


if __name__ == '__main__':
    main()
