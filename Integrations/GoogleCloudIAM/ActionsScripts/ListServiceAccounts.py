from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from GoogleCloudIAMManager import GoogleCloudIAMManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_IDENTIFIER,
    LIST_SERVICE_ACCOUNTS_SCRIPT_NAME,
    DEFAULT_MAX_SERVICE_ACCOUNTS_TO_RETURN
)
from utils import load_csv_to_list


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_IDENTIFIER} - {LIST_SERVICE_ACCOUNTS_SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # Integration configuration
    account_type = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Account Type",
        print_value=True
    )
    project_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Project ID",
        print_value=True
    )
    private_key_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Private Key ID",
        remove_whitespaces=False
    )
    private_key = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Private Key",
        remove_whitespaces=False
    )
    client_email = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Client Email",
        print_value=True
    )
    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Client ID",
        print_value=True
    )
    auth_uri = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Auth URI",
        print_value=True
    )
    token_uri = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Token URI",
        print_value=True
    )
    auth_provider_x509_url = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Auth Provider X509 URL",
        print_value=True
    )
    client_x509_url = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Client X509 URL",
        print_value=True
    )
    service_account_json = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Service Account Json File Content",
        remove_whitespaces=False
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Verify SSL",
        input_type=bool,
        print_value=True
    )

    # Action parameters
    service_account_display_name = extract_action_param(siemplify, param_name="Service Account Display Name", is_mandatory=False,
                                                        print_value=True)
    service_account_email = extract_action_param(siemplify, param_name="Service Account Email", is_mandatory=False, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    # Action results
    result_value = False
    status = EXECUTION_STATE_COMPLETED

    # Processing
    matched_service_accounts = {}

    try:
        max_service_accounts_to_return = extract_action_param(siemplify, param_name="Max Rows To Return", is_mandatory=False,
                                                              print_value=True, input_type=int, default_value=None)
        if max_service_accounts_to_return is not None and max_service_accounts_to_return <= 0:
            siemplify.LOGGER.info(f"\"Max Rows To Return\" must be positive. Using default of {DEFAULT_MAX_SERVICE_ACCOUNTS_TO_RETURN}.")
            max_service_accounts_to_return = DEFAULT_MAX_SERVICE_ACCOUNTS_TO_RETURN

        service_account_display_name_list = load_csv_to_list(service_account_display_name, "Service Account Display Name") if \
            service_account_display_name else []
        service_account_email_list = load_csv_to_list(service_account_email, "Service Account Email") if service_account_email else []

        manager = GoogleCloudIAMManager(
            account_type=account_type,
            project_id=project_id,
            private_key_id=private_key_id,
            private_key=private_key,
            client_email=client_email,
            client_id=client_id,
            auth_uri=auth_uri,
            token_uri=token_uri,
            auth_provider_x509_url=auth_provider_x509_url,
            client_x509_cert_url=client_x509_url,
            service_account_json=service_account_json,
            verify_ssl=verify_ssl,
            logger=siemplify.LOGGER
        )

        service_accounts = manager.list_service_accounts()

        if service_accounts:
            if service_account_email_list or service_account_display_name_list:
                # Match service accounts to provided input parameters
                for service_account in service_accounts:
                    # Filter by email
                    for email in service_account_email_list:
                        if email in service_account.email:
                            matched_service_accounts[service_account.email] = service_account
                            break
                    # Filter by display name if didn't matched by an email
                    if (service_account.email not in matched_service_accounts) and service_account_display_name_list:
                        for display_name in service_account_display_name_list:
                            if service_account.display_name and display_name in service_account.display_name:
                                matched_service_accounts[service_account.email] = service_account
                                break
                    if max_service_accounts_to_return and len(matched_service_accounts) >= max_service_accounts_to_return:
                        break
            else:
                service_accounts = service_accounts[
                                   :max_service_accounts_to_return] if max_service_accounts_to_return is not None else service_accounts
                matched_service_accounts = {service_account.email: service_account for service_account in service_accounts}

            if matched_service_accounts:
                output_message = f"Successfully fetched Google Cloud service accounts."
                result_value = True
                try:
                    matched_service_accounts_data_models = list(matched_service_accounts.values())
                    siemplify.result.add_result_json({
                        'accounts': [account.to_json() for account in matched_service_accounts_data_models]
                    })
                    siemplify.result.add_data_table(
                        title=f"Google Cloud Service Accounts",
                        data_table=construct_csv([account.to_csv() for account in matched_service_accounts_data_models])
                    )
                except Exception as error:
                    siemplify.LOGGER.error("Failed to add JSON/CSV Table results")
                    siemplify.LOGGER.exception(error)
            else:
                output_message = "No service accounts were returned for the specified input parameters."
        else:
            output_message = "No service accounts were found"

    except Exception as error:
        output_message = f"Error executing action \"{LIST_SERVICE_ACCOUNTS_SCRIPT_NAME}\". Reason: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
