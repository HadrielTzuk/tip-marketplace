from SiemplifyAction import SiemplifyAction
from McAfeeMvisionEPOV2Manager import McAfeeMvisionEPOV2Manager
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, construct_csv
from constants import ENRICH_ENDPOINT_SCRIPT_NAME, INTEGRATION_NAME, ENRICHMENT_PREFIX
from exceptions import DeviceNotFoundException
from SiemplifyDataModel import EntityTypes


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ENDPOINT_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    # Configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)

    iam_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='IAM Root',
                                           is_mandatory=True)

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client ID',
                                            is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client Secret',
                                                is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Key',
                                          is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=True, input_type=bool)

    scopes = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Scopes',
                                         is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    enriched_entities = []
    enriched_entity_identifiers = []
    output_message = ''
    json_results = {}
    missing_entities = []
    failed_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS
                         or entity.entity_type == EntityTypes.HOSTNAME]
    try:
        siemplify.LOGGER.info("Connecting to McAfee Mvision ePO V2.")
        manager = McAfeeMvisionEPOV2Manager(api_root, iam_root, client_id, client_secret, api_key, scopes, verify_ssl,
                                            siemplify.LOGGER)
        siemplify.LOGGER.info("Successfully connected to McAfee Mvision ePO V2.")

        devices = []

        for entity in suitable_entities:
            try:
                siemplify.LOGGER.info('Started processing entity: {}'.format(entity.identifier))

                device = manager.find_entity_or_fail(entity.identifier,
                                                     is_host=entity.entity_type == EntityTypes.HOSTNAME)
                devices.append(device)

                siemplify.LOGGER.info("Found device {} for entity {}.".format(device.device_id, entity.identifier))

                json_results[entity.identifier] = device.to_json()
                enriched_entity_identifiers.append(entity.identifier)
                enriched_entities.append(entity)
                entity.additional_properties.update(device.to_enrichment_data(ENRICHMENT_PREFIX))
                entity.is_enriched = True

                siemplify.add_entity_insight(entity, device.to_insight())

            except DeviceNotFoundException:
                missing_entities.append(entity.identifier)
                siemplify.LOGGER.error("No device was found for entity: {}".format(entity.identifier))

            except Exception as e:
                failed_entities.append(entity.identifier)
                siemplify.LOGGER.error("An error occurred on entity: {}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info('Finished processing entity: {}'.format(entity.identifier))

        if devices:
            siemplify.result.add_data_table(
                title='Devices',
                data_table=construct_csv([device.to_table_data() for device in devices])
            )

        if enriched_entities:
            siemplify.update_entities(enriched_entities)
            output_message += 'Successfully enriched the following endpoints from McAfee Mvision ePO V2: \n{}'.format(
                '\n'.join(enriched_entity_identifiers))

        else:
            siemplify.LOGGER.info('\n No entities were enriched.')
            output_message = 'No entities were enriched.'
            result_value = False

        if missing_entities:
            output_message += '\n\nAction was not able to find matching McAfee Mvision ePO V2 devices for the following endpoints: \n{}'.format(
                '\n'.join(missing_entities))

        if failed_entities:
            output_message += '\n\nAction was not able to enrich the following endpoints from McAfee Mvision ePO V2: \n{}\n'.format(
                '\n'.join(failed_entities))

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(
            ENRICH_ENDPOINT_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
