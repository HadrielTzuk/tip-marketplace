from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SCCMManager import SCCMManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param
from constants import INTEGRATION_NAME, PING_ACTION

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Server Address",
                                                 is_mandatory=True)
    domain = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Domain",
                                         is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        SCCMManager(server_address, domain, username, password)
        output_message = "Successfully connected to the Microsoft SCCM instance with the provided connection parameters!"
    except Exception as e:
        output_message = "Failed to connect to the Microsoft SCCM instance! The reason is: {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info(
        'Status: {}, Result Value: {}, Output Message: {}'
        .format(status, result_value, output_message)
    )

    siemplify.end(output_message, result_value, status)

if __name__ == '__main__':
    main()
