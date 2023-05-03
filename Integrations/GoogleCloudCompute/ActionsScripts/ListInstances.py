from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from GoogleCloudComputeManager import GoogleCloudComputeManager
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from consts import INTEGRATION_NAME, LIST_INSTANCES_TABLE_NAME, DEFAULT_MIN_RESULT, DEFAULT_MAX_RESULT
from utils import load_csv_to_list, create_filter_string
from exceptions import GoogleCloudComputeInvalidZone

SCRIPT_NAME = 'List Instances'


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
                                         input_type=str,
                                         is_mandatory=True,
                                         print_value=True)

    instance_name = extract_action_param(siemplify,
                                         param_name="Instance Name",
                                         input_type=str,
                                         is_mandatory=False,
                                         print_value=True)

    instance_status = extract_action_param(siemplify,
                                           param_name="Instance Status",
                                           input_type=str,
                                           is_mandatory=False,
                                           print_value=True)

    instance_labels = extract_action_param(siemplify,
                                           param_name="Instance Labels",
                                           input_type=str,
                                           is_mandatory=False,
                                           print_value=True)

    result_value = False

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    try:
        max_instances_to_return = extract_action_param(siemplify,
                                                       param_name="Max Rows to Return",
                                                       input_type=int,
                                                       is_mandatory=False,
                                                       print_value=True)

        if max_instances_to_return is not None and max_instances_to_return <= DEFAULT_MIN_RESULT:
            siemplify.LOGGER.info(
                f"Incorrect value was provided for Max Rows To Return. Using default value of {DEFAULT_MAX_RESULT} rows.")
            max_instances_to_return = DEFAULT_MAX_RESULT

        instances_names_list = load_csv_to_list(instance_name, "Instance Name") if instance_name else None
        instances_status_list = load_csv_to_list(instance_status, "Instance Status") if instance_status else None
        instances_labels_list = load_csv_to_list(instance_labels, "Instance Label") if instance_labels else None

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

        siemplify.LOGGER.info("Creates instances filter as a string")
        filters_string = create_filter_string(names=instances_names_list,
                                              statuses=instances_status_list,
                                              labels=instances_labels_list)
        siemplify.LOGGER.info("Successfully created instances filter as a string")

        instances = manager.list_instances(zone=instance_zone, limit=max_instances_to_return, filter=filters_string)

        if instances:
            siemplify.LOGGER.info("Creating JSON and table results")
            siemplify.result.add_result_json([instance.as_json() for instance in instances])
            siemplify.result.add_data_table(title=LIST_INSTANCES_TABLE_NAME,
                                            data_table=construct_csv([instance.as_csv() for instance in instances]))
            siemplify.LOGGER.info("Successfully created JSON and table results")
            output_message = f'Successfully fetched {INTEGRATION_NAME} instances.'
            result_value = True

        else:
            output_message = f"No instances were found in {INTEGRATION_NAME}."

        status = EXECUTION_STATE_COMPLETED

    except GoogleCloudComputeInvalidZone as e:
        siemplify.LOGGER.error(f"Provided instance zone {instance_zone} is not valid.")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_COMPLETED
        result_value = False
        output_message = f"Provided instance zone {instance_zone} is not valid."

    except Exception as e:
        siemplify.LOGGER.error(f"Error executing action {SCRIPT_NAME} Reason: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action {SCRIPT_NAME} Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
