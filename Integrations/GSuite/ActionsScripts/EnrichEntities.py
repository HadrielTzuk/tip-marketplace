from TIPCommon import extract_configuration_param

from GSuiteManager import GSuiteManager
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from consts import (
    INTEGRATION_NAME,
    ENRICH_ENTITIES_SCRIPT_NAME
)

SUPPORTED_ENTITIES = [EntityTypes.USER]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, ENRICH_ENTITIES_SCRIPT_NAME)
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INTEGRATION Configuration
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                            param_name="Client ID", is_mandatory=False, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name="Client Secret", is_mandatory=False, print_value=False)
    refresh_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name="Refresh Token", is_mandatory=False, print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool, print_value=True, is_mandatory=True)
    service_account_json = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                       param_name='Service Account JSON', is_mandatory=False,
                                                       print_value=False)

    delegated_email = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Delegated Email',
                                                  is_mandatory=False, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    enriched_entities = []  # list of successfully enriched entities
    failed_entities = []
    json_results = {}

    try:
        gsuite_manager = GSuiteManager(client_id=client_id, client_secret=client_secret, refresh_token=refresh_token,
                                       service_account_creds_path=service_account_json, delegated_email=delegated_email, verify_ssl=verify_ssl)
        for entity in siemplify.target_entities:
            if entity.entity_type not in SUPPORTED_ENTITIES:
                siemplify.LOGGER.info("Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                continue
            siemplify.LOGGER.info(f"Enriching entity {entity.identifier.strip()}")
            try:
                user = gsuite_manager.get_user(primary_email=entity.identifier.strip())
                siemplify.LOGGER.info(f"Successfully enriched entity {entity.identifier.strip()}")
                json_results[entity.identifier] = user.as_json()
                entity.is_enriched = True
                entity.additional_properties.update(user.as_enriched())
                enriched_entities.append(entity)

            except Exception as error:
                siemplify.LOGGER.error(f"Failed to enrich entity {entity.identifier} from {INTEGRATION_NAME}")
                siemplify.LOGGER.exception(error)
                failed_entities.append(entity.identifier)

        if enriched_entities:
            output_message = "The following entities were enriched:\n   {}\n\n".format(
                "\n   ".join([entity.identifier for entity in enriched_entities]))
            siemplify.update_entities(enriched_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
        else:
            output_message = 'No entities were enriched.\n\n'

        if failed_entities:
            output_message += "Action failed to enrich the following entities:\n   {}".format("\n   ".join(failed_entities))

    except Exception as error:
        output_message = f'Error executing action {ENRICH_ENTITIES_SCRIPT_NAME}. Reason: {error}'
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
