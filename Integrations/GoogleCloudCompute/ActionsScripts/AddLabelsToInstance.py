from TIPCommon import extract_configuration_param, extract_action_param

from GoogleCloudComputeManager import GoogleCloudComputeManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_NAME,
    ADD_LABELS_TO_INSTANCE_SCRIPT_NAME
)
from exceptions import (
    GoogleCloudComputeInvalidZone,
    GoogleCloudAuthenticationError,
    GoogleCloudComputeValidationError,
    GoogleCloudComputeInvalidInstanceID,
    GoogleCloudComputeLabelsValidationError
)
from utils import load_dict_from_csv_kv_list


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {ADD_LABELS_TO_INSTANCE_SCRIPT_NAME}"
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

    instance_labels = extract_action_param(siemplify,
                                           param_name="Instance Labels",
                                           is_mandatory=True,
                                           print_value=True)
    instance_labels_param = instance_labels
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = False
    output_message = ""

    try:
        instance_labels = load_dict_from_csv_kv_list(kv_csv=instance_labels, param_name="Instance Labels")
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
            instance_data = manager.get_instance(zone=instance_zone, resource_id=instance_id)
        except GoogleCloudComputeInvalidZone:
            raise
        except Exception as error:
            raise GoogleCloudComputeInvalidInstanceID(error)

        duplicated_label_keys = [label for label in instance_data.labels if label in instance_labels]
        keys_to_update = [label for label in instance_labels if label not in duplicated_label_keys]

        if keys_to_update:
            instance_data.labels.update({k: v for k, v in instance_labels.items() if k in keys_to_update})
            updated_instance = manager.set_labels_to_instance(project_id=project_id, zone=instance_zone, instance_id=instance_id,
                                                              labels=instance_data.labels,
                                                              label_fingerprint=instance_data.label_fingerprint)
            siemplify.result.add_result_json(updated_instance.to_json())
            result_value = True
            output_message += "Labels: {} were successfully added to {} instance {}\n\n".format(
                ",  ".join(":".join([key, instance_labels[key]]) for key in keys_to_update),
                INTEGRATION_NAME,
                instance_id
            )

        if duplicated_label_keys:
            output_message += "Labels were not added because provided labels: {} have keys that already exist for the {} instance {}".format(
                ",  ".join(":".join([key, instance_labels[key]]) for key in duplicated_label_keys),
                INTEGRATION_NAME,
                instance_id
            )

    except (GoogleCloudComputeValidationError, GoogleCloudComputeLabelsValidationError) as e:
        output_message = f"Provided instance labels: {instance_labels_param} are not in a valid format."
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    except GoogleCloudComputeInvalidInstanceID as e:
        output_message = f"Provided instance id: {instance_id} is not valid."
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    except GoogleCloudComputeInvalidZone as e:
        siemplify.LOGGER.error(f"Provided instance zone {instance_zone} is not valid.")
        siemplify.LOGGER.exception(e)
        output_message = f"Provided instance zone {instance_zone} is not valid."

    except Exception as e:
        output_message = f"Error executing action \"{ADD_LABELS_TO_INSTANCE_SCRIPT_NAME}\" Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
