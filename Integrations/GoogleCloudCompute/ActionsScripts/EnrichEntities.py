from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_unixtime_to_datetime, unix_now, convert_dict_to_json_result_dict, \
    add_prefix_to_dict
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from GoogleCloudComputeManager import GoogleCloudComputeManager
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from consts import INTEGRATION_NAME, ENRICHMENT_PREFIX, ENRICHMENT_CSV_TABLE_NAME
from utils import is_entity_contained_in_instance, get_instance_to_enrich_with, remove_none_from_dict
from exceptions import GoogleCloudComputeInvalidZone, GoogleCloudTransportException

SCRIPT_NAME = 'Enrich Entities'
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS]


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

    result_value = False
    json_results = {}
    successful_entities = []
    failed_entities = []
    output_message = ''
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

        siemplify.LOGGER.info(f"Fetching instances from {INTEGRATION_NAME} service")
        instances = manager.list_instances(zone=instance_zone)
        siemplify.LOGGER.info(f"Successfully fetched instances from {INTEGRATION_NAME} service")

        for entity in siemplify.target_entities:
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info("Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))

                entity_instances = []
                for instance in instances:
                    instance_network_interfaces = instance.network_interfaces

                    if not instance_network_interfaces:
                        continue

                    if is_entity_contained_in_instance(instance_network_interfaces=instance_network_interfaces,
                                                       ip_entity_address=entity.identifier):
                        siemplify.LOGGER.info(
                            f"The instance with ID {instance.id} contains the entity: {entity.identifier}")
                        entity_instances.append(instance)

                if not entity_instances:
                    siemplify.LOGGER.info(
                        f"No instance contained the entity: {entity.identifier}. The entity will not be enriched")
                    continue

                enriching_instance = get_instance_to_enrich_with(entity_instances)
                siemplify.LOGGER.info(f"The entity {entity.identifier} will be enriched with the instance with id:"
                                      f" {enriching_instance.id}")

                #  Enrichment:
                enrichment_data = add_prefix_to_dict(enriching_instance.as_enrichment(), ENRICHMENT_PREFIX)
                enrichment_data_without_none = remove_none_from_dict(enrichment_data)
                entity.additional_properties.update(enrichment_data_without_none)
                entity.is_enriched = True

                #  JSON and CSV handling:
                json_results[entity.identifier] = enriching_instance.as_json()
                siemplify.result.add_data_table(title=ENRICHMENT_CSV_TABLE_NAME.format(entity.identifier), data_table=
                                                  construct_csv(enriching_instance.as_enrichment_csv(
                                                      enrichment_data_without_none)))

                successful_entities.append(entity)
                siemplify.LOGGER.info(f"Finished processing entity {entity.identifier}")

            except GoogleCloudTransportException as e:
                raise e

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error(f"An error occurred on entity {entity.identifier}")
                siemplify.LOGGER.exception(e)

        if not successful_entities:
            output_message += "No entities were enriched."

        else:
            result_value = True
            output_message += f"Successfully enriched entities: {', '.join([ent.identifier for ent in successful_entities])}\n"
            output_message += f"Action was not able to find a match {INTEGRATION_NAME} to enrich provided " \
                              f"entities: {', '.join([ent.identifier for ent in failed_entities])}" if failed_entities else ''
            siemplify.update_entities(successful_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

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
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
