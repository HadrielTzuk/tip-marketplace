from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from ActiveDirectoryManager import ActiveDirectoryManager

# =====================================
#             CONSTANTS               #
# =====================================
INTEGRATION_NAME = "ActiveDirectory"
SCRIPT_NAME = "ActiveDirectory - Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    output_message = ""

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATIONS:
    server = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Server", input_type=str
    )
    username = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Username", input_type=str
    )
    password = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Password", input_type=str
    )
    domain = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Domain", input_type=str
    )
    use_ssl = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Use SSL", input_type=bool
    )
    custom_query_fields = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="Custom Query Fields", input_type=str
    )
    ca_certificate = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="CA Certificate File - parsed into Base64 String"
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    try:
        #  If no exception
        manager = ActiveDirectoryManager(server, domain, username, password, use_ssl, custom_query_fields,
                                         ca_certificate, siemplify.LOGGER)
        manager.test_connectivity(username)
        status = EXECUTION_STATE_COMPLETED
        output_message += "Connection Established"
        siemplify.LOGGER.info("Finished processing")
        result_value = True
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}. Error: {}".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message += "General error performing action {}. Error: {}".format(SCRIPT_NAME, e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        "\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
