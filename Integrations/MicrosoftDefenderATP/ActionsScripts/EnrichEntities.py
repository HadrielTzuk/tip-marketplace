from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict, add_prefix_to_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, construct_csv
from MicrosoftDefenderATPManager import MicrosoftDefenderATPManager, MicrosoftDefenderATPError

PROVIDER_NAME = u'MicrosoftDefenderATP'
SCRIPT_NAME = u'{} - Enrich Entities'.format(PROVIDER_NAME)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Api Root",
        input_type=unicode
    )

    client_id = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Client ID",
        input_type=unicode
    )

    client_secret = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Client Secret",
        input_type=unicode
    )

    tenant_id = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Azure Active Directory ID",
        input_type=unicode
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Verify SSL",
        input_type=bool,
        default_value=False
    )

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    json_result = {}
    failed_entities = []
    missing_entities = []
    enriched_entities = []

    try:
        microsoft_defender_atp = MicrosoftDefenderATPManager(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            resource=api_root,
            verify_ssl=verify_ssl
        )

        for entity in siemplify.target_entities:
            siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
            if entity.entity_type in [EntityTypes.HOSTNAME, EntityTypes.ADDRESS]:
                if entity.entity_type == EntityTypes.HOSTNAME:
                    machines = microsoft_defender_atp.get_machines_by_name(starts_with_name=entity.identifier)
                else:
                    machines = microsoft_defender_atp.get_machines(ip=entity.identifier)

                if machines:
                    found_machine = machines[-1]

                    enrichment_data = add_prefix_to_dict(found_machine.to_enrichment_data(), u'Defender ATP')
                    entity.additional_properties.update(enrichment_data)
                    entity.is_enriched = True

                    enriched_entities.append(entity)

                    json_result[entity.identifier] = found_machine.to_json()
                    siemplify.result.add_entity_json(
                        entity_identifier=entity.identifier,
                        json_data=found_machine.to_json()
                    )

                    siemplify.result.add_entity_table(
                        entity_identifier=entity.identifier,
                        data_table=construct_csv([found_machine.to_table()])
                    )
                else:
                    missing_entities.append(entity)
                    siemplify.LOGGER.info(
                        u'Entity {} was not enriched because nothing was found'.format(entity.identifier)
                    )

            elif entity.entity_type == EntityTypes.FILEHASH:
                try:
                    file_data = microsoft_defender_atp.get_file(entity.identifier)
                    enrichment_data = add_prefix_to_dict(file_data.to_enrichment_data(), u'Defender ATP')
                    entity.additional_properties.update(enrichment_data)
                    entity.is_enriched = True

                    enriched_entities.append(entity)

                    json_result[entity.identifier] = file_data.to_json()
                    siemplify.result.add_entity_json(
                        entity_identifier=entity.identifier,
                        json_data=file_data.to_json()
                    )

                    siemplify.result.add_entity_table(
                        entity_identifier=entity.identifier,
                        data_table=construct_csv([file_data.to_table()])
                    )
                except MicrosoftDefenderATPError as e:
                    siemplify.LOGGER.error(e)
                    siemplify.LOGGER.exception(e)
                    failed_entities.append(entity)

            else:
                siemplify.LOGGER.info(u'Entity {} is of unsupported type, skipping...'.format(entity.identifier))

            siemplify.LOGGER.info(u"Finished processing entity {}".format(entity.identifier))

        output_messages = [
            u'{} entities enriched'.format(len(enriched_entities)),
            u'{} entities missed'.format(len(missing_entities)),
            u'{} entities failed'.format(len(failed_entities))
        ]

        if enriched_entities:
            siemplify.update_entities(enriched_entities)

            output_messages.append(u'Enriched Entities: {}'.format(
                MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(
                    [entity.identifier for entity in enriched_entities]
                )
            ))

            output_messages.append(u'Missing Entities: {}'.format(
                MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(
                    [entity.identifier for entity in missing_entities]
                )
            ))

            output_messages.append(u'Failed Entities: {}'.format(
                MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(
                    [entity.identifier for entity in missing_entities]
                )
            ))

            result = u'true'
        else:
            output_messages.append(u'No entities were enriched')
            result = u'false'
            siemplify.LOGGER.warn(u'No entities were enriched')

        status = EXECUTION_STATE_COMPLETED
        output_message = u'\n'.join(output_messages)

    except MicrosoftDefenderATPError as e:
        output_message = u'Action didn\'t completed due to error: {}'.format(e)
        result = u'false'
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u'Status: {}'.format(status))
    siemplify.LOGGER.info(u'Result: {}'.format(result))
    siemplify.LOGGER.info(u'Output Message: {}'.format(output_message))
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_result))
    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
