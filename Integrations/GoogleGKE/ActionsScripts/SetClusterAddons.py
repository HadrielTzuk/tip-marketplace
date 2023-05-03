import json
import sys

from TIPCommon import extract_configuration_param, extract_action_param

from GoogleGKEManager import GoogleGKEManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_IDENTIFIER,
    SET_CLUSTER_ADDONS_SCRIPT_NAME,
    NOT_CHANGED,
    DISABLED,
    MAP_CLOUD_RUN_CONFIG_PARAMS,
    ENABLED
)
from exceptions import (
    GoogleGKEManagerError,
    GoogleGKEInvalidZoneError,
    GoogleGKEInvalidClusterNameError,
    MissingParametersException
)
from utils import is_action_approaching_timeout


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_IDENTIFIER} - {SET_CLUSTER_ADDONS_SCRIPT_NAME}"
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
    http_load_balancing = extract_action_param(siemplify, param_name="HTTP Load Balancing", is_mandatory=False, default_value=NOT_CHANGED,
                                               print_value=True)
    horizontal_pod_autoscaling = extract_action_param(siemplify, param_name="Horizontal Pod Autoscaling", is_mandatory=False,
                                                      default_value=NOT_CHANGED, print_value=True)
    network_policy_config = extract_action_param(siemplify, param_name="Network Policy Config", is_mandatory=False, default_value=NOT_CHANGED,
                                                 print_value=True)
    cloud_run_config = extract_action_param(siemplify, param_name="Cloud Run Config", is_mandatory=False, default_value=NOT_CHANGED, print_value=True)
    dns_cache_record = extract_action_param(siemplify, param_name="DNS Cache Config", is_mandatory=False, default_value=NOT_CHANGED, print_value=True)
    config_connector_config = extract_action_param(siemplify, param_name="Config Connector Config", is_mandatory=False, default_value=NOT_CHANGED,
                                                   print_value=True)
    gce_persistent_disk_csi_driver_config = extract_action_param(siemplify, param_name="GCE Persistent Disk Csi Driver Config", is_mandatory=False,
                                                                 default_value=NOT_CHANGED,
                                                                 print_value=True)

    wait_for_operation_to_finish = extract_action_param(siemplify, param_name="Wait for cluster configuration change operation to finish",
                                                        is_mandatory=True, input_type=bool, print_value=True)

    siemplify.LOGGER.info("----------------- {} - Started -----------------".format(mode))

    # Action results
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    operation = None

    try:
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
                if not any(conf != NOT_CHANGED for conf in [http_load_balancing, horizontal_pod_autoscaling, network_policy_config, cloud_run_config,
                                                            dns_cache_record, config_connector_config, gce_persistent_disk_csi_driver_config]):
                    raise MissingParametersException("Provided parameters must specify at least one addon config.")

                cloud_run_config_is_disabled, cloud_run_config_load_balancer_type = MAP_CLOUD_RUN_CONFIG_PARAMS.get(cloud_run_config, (None, None))
                operation = manager.update_cluster_addons(
                    cluster_location, cluster_name,
                    http_load_balancing_disabled=http_load_balancing == DISABLED if http_load_balancing != NOT_CHANGED else None,
                    horizontal_pod_autoscaling_disabled=horizontal_pod_autoscaling == DISABLED if horizontal_pod_autoscaling != NOT_CHANGED else None,
                    network_policy_config_disabled=network_policy_config == DISABLED if network_policy_config != NOT_CHANGED else None,
                    cloud_run_config_disabled=cloud_run_config_is_disabled,
                    cloud_run_config_load_balancer_type=cloud_run_config_load_balancer_type,
                    dns_cache_config_enabled=dns_cache_record == ENABLED if dns_cache_record != NOT_CHANGED else None,
                    config_connector_config_enabled=config_connector_config == ENABLED if config_connector_config != NOT_CHANGED else None,
                    gce_persistent_disk_csi_driver_config_enabled=gce_persistent_disk_csi_driver_config == ENABLED if gce_persistent_disk_csi_driver_config != NOT_CHANGED else None
                )
                if wait_for_operation_to_finish:
                    output_message, result_value, status = manager.gke_common.check_operation_status(operation,
                                                                                                     is_action_approaching_timeout(
                                                                                                         siemplify.execution_deadline_unix_time_ms))
                else:
                    output_message = "Successfully created cluster configuration change operation."
                    result_value = True
            except (GoogleGKEInvalidClusterNameError, GoogleGKEInvalidZoneError):
                raise
            except GoogleGKEManagerError as error:
                output_message = f"Failed to execute the action because API returned error, please see action logs: {error}"
                siemplify.LOGGER.error(f"Failed to update cluster with specified addons")
                siemplify.LOGGER.exception(error)
        else:
            operation_name = json.loads(siemplify.parameters["additional_data"])
            operation = manager.get_operation(cluster_location, operation_name, cluster_name)
            output_message, result_value, status = manager.gke_common.check_operation_status(operation,
                                                                                             is_action_approaching_timeout(
                                                                                                 siemplify.execution_deadline_unix_time_ms))

        if operation and status != EXECUTION_STATE_INPROGRESS:  # append json results only if action's execution is finished
            siemplify.result.add_result_json(operation.to_json())

    except (GoogleGKEInvalidClusterNameError, MissingParametersException) as error:
        output_message = f"{error}"
        status = EXECUTION_STATE_FAILED

    except GoogleGKEInvalidZoneError:
        output_message = f"Provided cluster location \"{cluster_location}\" does not exist."
        status = EXECUTION_STATE_FAILED

    except Exception as error:
        output_message = f"Error execution action \"{SET_CLUSTER_ADDONS_SCRIPT_NAME}\". Reason: {error}"
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
