from SiemplifyUtils import output_handler
from GoogleBigQueryManager import GoogleBigQueryManager
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv


INTEGRATION_NAME = "GoogleBigQuery"
SCRIPT_NAME = "Run SQL Query"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    account_type = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Account Type",
        print_value=True
    )
    project_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Project ID",
        print_value=True
    )
    private_key_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Private Key ID",
        remove_whitespaces=False
    )
    private_key = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Private Key",
        remove_whitespaces=False
    )
    client_email = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Client Email",
        print_value=True
    )
    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Client ID",
        print_value=True
    )
    auth_uri = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Auth URI",
        print_value=True
    )
    token_uri = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Token URI",
        print_value=True
    )
    auth_provider_x509_url = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Auth Provider X509 URL",
        print_value=True
    )
    client_x509_url = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Client X509 URL",
        print_value=True
    )
    service_account_json = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Service Account Json File Content",
        remove_whitespaces=False
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Verify SSL",
        input_type=bool,
        print_value=True
    )

    dataset_name = extract_action_param(siemplify, param_name="Dataset Name", is_mandatory=True, print_value=True)
    query = extract_action_param(siemplify, param_name="Query", is_mandatory=True, print_value=True)
    limit = extract_action_param(siemplify, param_name="Max Results To Return", is_mandatory=False, print_value=True,
                                 default_value=None, input_type=int)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    results = []
    status = EXECUTION_STATE_COMPLETED
    result_value = "true"

    try:
        big_query_manager = GoogleBigQueryManager(
            account_type=account_type,
            project_id=project_id,
            private_key_id=private_key_id,
            private_key=private_key,
            client_email=client_email,
            client_id=client_id,
            auth_uri=auth_uri,
            token_uri=token_uri,
            auth_provider_x509_cert_url=auth_provider_x509_url,
            client_x509_cert_url=client_x509_url,
            service_account_json=service_account_json,
            verify_ssl=verify_ssl
        )
        results = big_query_manager.run_query(dataset_name=dataset_name, query=query, limit=limit)

        siemplify.LOGGER.info(f"Found {len(results)} rows.")

        if results:
            siemplify.result.add_data_table("Results", construct_csv(results))

        output_message = f"Successfully executed query in the Google BigQuery dataset \"{dataset_name}\"!"

    except Exception as e:
        siemplify.LOGGER.error(f"Error executing action \"Run SQL Query\". Reason: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = f"Error executing action \"Run SQL Query\". Reason: {e}"

    siemplify.result.add_result_json(results)
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
