from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from GoogleGKEManager import GoogleGKEManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_IDENTIFIER,
    INTEGRATION_DISPLAY_NAME,
    LIST_OPERATIONS_SCRIPT_NAME,
    ALL_CLUSTERS
)
from datamodels import FilterLogicParam, KubeClusterOperation
from exceptions import (
    GoogleGKEInvalidZoneError,
    NegativeValueException
)
from utils import (
    get_filtered_objects
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_IDENTIFIER} - {LIST_OPERATIONS_SCRIPT_NAME}"
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
    cluster_location = extract_action_param(siemplify, param_name="Location", is_mandatory=True, print_value=True)
    filter_logic = extract_action_param(siemplify, param_name="Filter Logic", default_value=f"{FilterLogicParam.Equal}", is_mandatory=False,
                                        print_value=True)
    filter_value = extract_action_param(siemplify, param_name="Filter Value", is_mandatory=False, print_value=True)

    # Action results
    result_value = False
    status = EXECUTION_STATE_COMPLETED

    try:
        max_records_to_return = extract_action_param(siemplify, param_name="Max Records To Return", is_mandatory=False,
                                                     print_value=True, input_type=int, default_value=50)
        if max_records_to_return <= 0:
            raise NegativeValueException(
                f"Invalid value was provided for \"Max Records to Return\": {max_records_to_return}. Positive number should be provided.")

        manager = GoogleGKEManager(
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

        operations = manager.list_operations(cluster_location)
        siemplify.LOGGER.info(
            f"Found {len(operations)} operations in {f'zone {cluster_location}' if cluster_location != ALL_CLUSTERS else 'all zones'} in {INTEGRATION_DISPLAY_NAME}")

        if filter_value:
            filtered_operations = get_filtered_objects(operations, KubeClusterOperation.get_name_attribute(), filter_logic, filter_value)
            siemplify.LOGGER.info(f"Filtered {len(filtered_operations)} operations by filter logic \"{filter_logic}\" and value {filter_value}")
        else:
            filtered_operations = operations
        filtered_operations = filtered_operations[:max_records_to_return]
        if filtered_operations:
            output_message = f"Successfully found operations for cluster for the provided criteria in {INTEGRATION_DISPLAY_NAME}."
            result_value = True
            siemplify.result.add_data_table("Found Operations", construct_csv([operation.to_csv() for operation in filtered_operations]))
            siemplify.result.add_result_json({"operations": [operation.to_json() for operation in filtered_operations]})
        else:
            output_message = f"No operations were found for the provided criteria in {INTEGRATION_DISPLAY_NAME}."

    except NegativeValueException as error:
        output_message = f"{error}"
        status = EXECUTION_STATE_FAILED

    except GoogleGKEInvalidZoneError:
        output_message = f"Provided cluster location \"{cluster_location}\" does not exist."
        status = EXECUTION_STATE_FAILED

    except Exception as error:
        output_message = f"Error execution action \"{LIST_OPERATIONS_SCRIPT_NAME}\". Reason: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
