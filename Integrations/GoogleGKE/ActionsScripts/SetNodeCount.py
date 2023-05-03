import json
import sys

from TIPCommon import extract_configuration_param, extract_action_param

from GoogleGKEManager import GoogleGKEManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_IDENTIFIER,
    SET_NODE_POOL_COUNT_SCRIPT_NAME
)
from exceptions import (
    GoogleGKEManagerError,
    GoogleGKEInvalidZoneError,
    GoogleGKEInvalidClusterNameError,
    GoogleGKEInvalidNodePoolNameError,
    MissingParametersException,
    NonPositiveValueException
)
from utils import is_action_approaching_timeout


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_IDENTIFIER} - {SET_NODE_POOL_COUNT_SCRIPT_NAME}"
    mode = "Main" if is_first_run else "Check changes"
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
    cluster_location = extract_action_param(siemplify, param_name="Cluster Location", is_mandatory=True, print_value=True)
    cluster_name = extract_action_param(siemplify, param_name="Cluster Name", is_mandatory=True, print_value=True)
    node_pool_name = extract_action_param(siemplify, param_name="Node Pool Name", is_mandatory=True, print_value=True)
    wait_for_operation_to_finish = extract_action_param(siemplify, param_name="Wait for cluster configuration change operation to finish",
                                                        is_mandatory=True, input_type=bool, print_value=True)
    siemplify.LOGGER.info("----------------- {} - Started -----------------".format(mode))

    # Action results
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    operation = None

    try:
        node_count = extract_action_param(siemplify, param_name="Node Count", is_mandatory=True, print_value=True, input_type=int)
        if node_count < 0:
            raise NonPositiveValueException(
                f"Invalid value was provided for \"Node Count\": {node_count}. Value should be a positive number.")

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
            verify_ssl=verify_ssl,
            logger=siemplify.LOGGER
        )

        if is_first_run:
            try:
                operation = manager.set_cluster_node_pool_count(zone_name=cluster_location, cluster_name=cluster_name, node_pool_name=node_pool_name,
                                                                node_count=node_count)

                if wait_for_operation_to_finish:
                    output_message, result_value, status = manager.gke_common.check_operation_status(operation,
                                                                                                     is_action_approaching_timeout(
                                                                                                         siemplify.execution_deadline_unix_time_ms))
                else:
                    output_message = "Successfully created cluster node pool configuration change operation."
                    result_value = True
            except (GoogleGKEInvalidZoneError, GoogleGKEInvalidClusterNameError, GoogleGKEInvalidNodePoolNameError):
                raise
            except GoogleGKEManagerError as error:
                output_message = f"Failed to execute the action because API returned error, please see action logs: {error}"
                siemplify.LOGGER.error(f"Failed to set node autoscaling config")
                siemplify.LOGGER.exception(error)
        else:
            operation_name = json.loads(siemplify.parameters["additional_data"])
            operation = manager.get_operation(cluster_location, operation_name, cluster_name)
            output_message, result_value, status = manager.gke_common.check_operation_status(operation,
                                                                                             is_action_approaching_timeout(
                                                                                                 siemplify.execution_deadline_unix_time_ms))

        if operation and status != EXECUTION_STATE_INPROGRESS:  # append json results only if action's execution is finished
            siemplify.result.add_result_json(operation.to_json())

    except (GoogleGKEInvalidNodePoolNameError, GoogleGKEInvalidClusterNameError, MissingParametersException) as error:
        output_message = f"{error}"
        status = EXECUTION_STATE_FAILED

    except GoogleGKEInvalidZoneError:
        output_message = f"Provided cluster location \"{cluster_location}\" does not exist."
        status = EXECUTION_STATE_FAILED

    except Exception as error:
        output_message = f"Error execution action \"{SET_NODE_POOL_COUNT_SCRIPT_NAME}\". Reason: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- {} - Finished -----------------".format(mode))
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == 'True'
    main(is_first_run)
