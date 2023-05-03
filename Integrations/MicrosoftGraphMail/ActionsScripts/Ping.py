from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from MicrosoftGraphMailManager import MicrosoftGraphMailManager
from TIPCommon import extract_configuration_param

INTEGRATION_NAME = "MicrosoftGraphMail"
SCRIPT_NAME = "Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    azure_ad_endpoint = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Azure AD Endpoint",
        is_mandatory=True,
        input_type=str,
        print_value=True
    )
    microsoft_graph_endpoint = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Microsoft Graph Endpoint",
        is_mandatory=True,
        input_type=str,
        print_value=True
    )
    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Client ID",
        is_mandatory=True,
        input_type=str,
        print_value=True
    )
    secret_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Secret ID",
        is_mandatory=True,
        input_type=str,
        remove_whitespaces=False
    )
    tenant = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Tenant",
        is_mandatory=True,
        input_type=str,
        print_value=True
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Verify SSL",
        is_mandatory=True,
        input_type=bool,
        print_value=True
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        siemplify.LOGGER.info("Connecting to Microsoft Graph Mail.")
        microsoft_graph_mail_manager = MicrosoftGraphMailManager(
            azure_ad_endpoint=azure_ad_endpoint,
            microsoft_graph_endpoint=microsoft_graph_endpoint,
            client_id=client_id,
            client_secret=secret_id,
            tenant=tenant,
            verify_ssl=verify_ssl
        )
        siemplify.LOGGER.info("Connected successfully.")

        output_message = "Connection Established"
        result_value = 'true'
        status = EXECUTION_STATE_COMPLETED

    except Exception as e:
        siemplify.LOGGER.error(f"Some errors occurred. Error: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = f"Some errors occurred. Error: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
