from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from constants import SHA256_LENGTH, MD5_LENGTH, SHA1_LENGTH
from MicrosoftDefenderATPManager import MicrosoftDefenderATPManager, MicrosoftDefenderATPError
from UtilsManager import get_entity_original_identifier

PROVIDER_NAME = u'MicrosoftDefenderATP'
SCRIPT_NAME = u'{} - Delete Entity Indicators'.format(PROVIDER_NAME)
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.FILEHASH, EntityTypes.URL]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Api Root",
                                           input_type=unicode, is_mandatory=True)
    client_id = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Client ID",
                                            input_type=unicode, is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Client Secret",
                                                input_type=unicode, is_mandatory=True)
    tenant_id = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME,
                                            param_name="Azure Active Directory ID", input_type=unicode,
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Verify SSL",
                                             input_type=bool, is_mandatory=True, default_value=False)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_messages = []
    successful_entities = []
    failed_entities = []
    not_found_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITIES]

    try:
        microsoft_defender_atp = MicrosoftDefenderATPManager(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            resource=api_root,
            verify_ssl=verify_ssl,
            siemplify=siemplify,
            entities_scope=True
        )

        indicators = microsoft_defender_atp.get_entities(entities=[get_entity_original_identifier(entity)
                                                                   for entity in suitable_entities])

        for entity in suitable_entities:
            siemplify.LOGGER.info(u'Started processing entity {}'.format(entity.identifier))
            entity_identifier = get_entity_original_identifier(entity)

            if entity.entity_type == EntityTypes.FILEHASH:
                if len(entity_identifier) not in [SHA256_LENGTH, MD5_LENGTH, SHA1_LENGTH]:
                    siemplify.LOGGER.error(u"Not supported hash type. Provide either MD5, SHA-256 or SHA-1.")
                    siemplify.LOGGER.info(u"Finished processing entity {}".format(entity.identifier))
                    continue

            matching_indicators = [indicator for indicator in indicators if indicator.indicator_value.lower() ==
                                   entity_identifier.lower()]

            if not matching_indicators:
                not_found_entities.append(entity)
            else:
                for indicator in matching_indicators:
                    try:
                        microsoft_defender_atp.delete_indicator(indicator_id=indicator.identifier)
                        successful_entities.append(entity)
                    except MicrosoftDefenderATPError as e:
                        failed_entities.append(entity)
                        siemplify.LOGGER.error(u"An error occurred on entity: {}".format(entity.identifier))
                        siemplify.LOGGER.exception(e)
            siemplify.LOGGER.info(u"Finished processing entity {}".format(entity.identifier))

        if successful_entities:
            output_messages.append(u'Successfully deleted the following entities as indicators in Microsoft Defender '
                                   u'ATP: {}'.format(MicrosoftDefenderATPManager.
                                                     convert_list_to_comma_separated_string([entity.identifier
                                                                                             for entity in
                                                                                             successful_entities])))

            if failed_entities:
                output_messages.append(
                    u"Action wasn't able to delete the following entities as indicators in Microsoft Defender "
                    u"ATP: {}".format(MicrosoftDefenderATPManager.
                                      convert_list_to_comma_separated_string([entity.identifier for entity in
                                                                              failed_entities])))
        elif not not_found_entities:
            output_messages.append(u'None of the provided entities were deleted as indicators in Microsoft '
                                   u'Defender ATP.')
            result_value = False

        if not_found_entities:
            output_messages.append(
                u"The following entities don't exist as indicators in Microsoft Defender "
                u"ATP: {}".format(MicrosoftDefenderATPManager.
                                  convert_list_to_comma_separated_string([entity.identifier for entity in
                                                                          not_found_entities])))

        output_message = u'\n'.join(output_messages)

    except MicrosoftDefenderATPError as e:
        output_message = u"Error executing action '{}'. Reason: {}".format(SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u'Status: {}'.format(status))
    siemplify.LOGGER.info(u'Result: {}'.format(result_value))
    siemplify.LOGGER.info(u'Output Message: {}'.format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
