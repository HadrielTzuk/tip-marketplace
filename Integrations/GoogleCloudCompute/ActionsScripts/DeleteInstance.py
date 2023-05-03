from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from GoogleCloudComputeManager import GoogleCloudComputeManager
from TIPCommon import extract_configuration_param, extract_action_param
from consts import INTEGRATION_NAME
from exceptions import GoogleCloudComputeInvalidZone, GoogleCloudComputeInvalidInstanceID
from utils import extract_name_from_address

SCRIPT_NAME = 'Delete Instance'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # Integration configuration
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

    instance_zone = extract_action_param(siemplify,
                                         param_name="Instance Zone",
                                         is_mandatory=True,
                                         print_value=True)

    instance_id = extract_action_param(siemplify,
                                       param_name="Instance ID",
                                       is_mandatory=True,
                                       print_value=True)

    result_value = True
    status = EXECUTION_STATE_COMPLETED

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    try:
        manager = GoogleCloudComputeManager(
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
            verify_ssl=verify_ssl
        )

        siemplify.LOGGER.info(f"Deleting instance with ID: {instance_id}")
        operation_raw_data = manager.delete_instance(zone=instance_zone, instance_id=instance_id)
        siemplify.LOGGER.info(f"Successfully deleted instance with ID: {instance_id}")

        if operation_raw_data:
            operation_raw_data['zone'] = extract_name_from_address(operation_raw_data.get('zone', ""))

        siemplify.result.add_result_json(operation_raw_data)
        output_message = f"{INTEGRATION_NAME} instance {instance_id} was deleted successfully."

    except GoogleCloudComputeInvalidZone as error:
        siemplify.LOGGER.error(f"Provided instance zone {instance_zone} is not valid.")
        siemplify.LOGGER.exception(error)
        result_value = False
        output_message = f"Provided instance zone {instance_zone} is not valid."

    except GoogleCloudComputeInvalidInstanceID as error:
        siemplify.LOGGER.error(f"Provided instance id {instance_id} is not valid.")
        siemplify.LOGGER.exception(error)
        result_value = False
        output_message = f"Provided instance id {instance_id} is not valid."

    except Exception as error:
        siemplify.LOGGER.error(f"Error executing action {SCRIPT_NAME} Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action {SCRIPT_NAME} Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
