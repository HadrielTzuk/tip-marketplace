from collections import defaultdict

from TIPCommon import extract_configuration_param

from GoogleCloudIAMManager import GoogleCloudIAMManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime, convert_dict_to_json_result_dict, construct_csv
from consts import (
    INTEGRATION_IDENTIFIER,
    INTEGRATION_DISPLAY_NAME,
    ENRICH_ENTITIES_SCRIPT_NAME,
)

SUPPORTED_ENTITIES = [EntityTypes.USER]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_IDENTIFIER} - {ENRICH_ENTITIES_SCRIPT_NAME}"
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

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    # Action results
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    json_results = defaultdict(dict)

    # Processing
    successful_entities = []
    failed_entities = []

    try:
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
        supported_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITIES]

        if not supported_entities:
            siemplify.LOGGER.info("No suitable entities were found")
            siemplify.end("No entities were enriched", False, EXECUTION_STATE_COMPLETED)

        siemplify.LOGGER.info(f"Listing service accounts")
        service_accounts = manager.list_service_accounts()
        service_accounts_by_emails = {service_account.email.lower(): service_account for service_account in
                                      service_accounts if service_account.email}

        siemplify.LOGGER.info(f"Successfully listed {len(service_accounts)} service accounts")

        if not service_accounts:
            siemplify.end("No entities were enriched", False, EXECUTION_STATE_COMPLETED)

        for entity in supported_entities:
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break
            try:
                siemplify.LOGGER.info(f"Started processing entity: {entity.identifier}")

                # Match by email
                if entity.identifier.strip().lower() in service_accounts_by_emails:
                    entity_service_account = service_accounts_by_emails[entity.identifier.strip().lower()]
                else:
                    siemplify.LOGGER.info(f"No matched service account")
                    failed_entities.append(entity)
                    continue

                entity_enrichment_table = {}
                siemplify.LOGGER.info(f"Successfully matched service account for entity")
                json_results[entity.identifier].update(entity_service_account.to_json())
                entity_enrichment_table.update(entity_service_account.to_enrichment())

                siemplify.result.add_data_table(
                    title=f'{entity.identifier} Enrichment Table',
                    data_table=construct_csv(
                        [{'Key': k, 'Value': v} for k, v in entity_enrichment_table.items() if v or isinstance(v, int)])
                )
                entity.additional_properties.update(entity_enrichment_table)
                entity.is_enriched = True
                successful_entities.append(entity)
                siemplify.LOGGER.info(f"Finished processing entity {entity.identifier}")
            except Exception as error:
                failed_entities.append(entity)
                siemplify.LOGGER.error(f"An error occurred on entity {entity.identifier}")
                siemplify.LOGGER.exception(error)

        if successful_entities:
            output_message += "Successfully enriched entities:\n   {}".format(
                "\n   ".join([entity.identifier for entity in successful_entities])
            )
            siemplify.update_entities(successful_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            result_value = True
            if failed_entities:
                output_message += "\n\nAction was not able to find a match in {} to enrich provided entities:\n   {}".format(
                    INTEGRATION_DISPLAY_NAME,
                    "\n   ".join([entity.identifier for entity in failed_entities])
                )
        else:
            output_message += "No entities were enriched"

    except Exception as error:
        output_message = f"Error executing action \"{ENRICH_ENTITIES_SCRIPT_NAME}\". Reason: {error}"
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
