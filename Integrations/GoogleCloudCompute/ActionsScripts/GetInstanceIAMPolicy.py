from TIPCommon import extract_configuration_param, extract_action_param

from GoogleCloudComputeManager import GoogleCloudComputeManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, GET_INSTANCE_IAM_POLICY_SCRIPT_NAME
from exceptions import GoogleCloudComputeInvalidZone, GoogleCloudAuthenticationError, GoogleCloudComputeInvalidInstanceID


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {GET_INSTANCE_IAM_POLICY_SCRIPT_NAME}"
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

    instance_zone = extract_action_param(siemplify, param_name="Instance Zone", is_mandatory=True, print_value=True)
    instance_id = extract_action_param(siemplify, param_name="Instance ID", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
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
                force_test_connectivity=True,
                service_account_json=service_account_json,
                verify_ssl=verify_ssl
            )
        except Exception as error:
            raise GoogleCloudAuthenticationError(f"Authentication Error - {error}")

        try:
            instance_iam_policy = manager.get_instance_iam_policy(zone=instance_zone, project_id=project_id, instance_id=instance_id)
        except GoogleCloudComputeInvalidZone:
            raise
        except Exception as error:
            raise GoogleCloudComputeInvalidInstanceID(error)

        siemplify.result.add_result_json(instance_iam_policy.to_json())
        output_message = f'{INTEGRATION_NAME} instance {instance_id} IAM policy was fetched successfully.'
        result_value = True
        status = EXECUTION_STATE_COMPLETED

    except GoogleCloudComputeInvalidZone as e:
        output_message = f"Provided instance zone {instance_zone} is not valid."
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_COMPLETED
        result_value = False

    except GoogleCloudComputeInvalidInstanceID as e:
        output_message = f"Provided instance id {instance_id} is not valid."
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_COMPLETED
        result_value = False

    except Exception as e:
        output_message = f"Error executing action \"{GET_INSTANCE_IAM_POLICY_SCRIPT_NAME}\" Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
