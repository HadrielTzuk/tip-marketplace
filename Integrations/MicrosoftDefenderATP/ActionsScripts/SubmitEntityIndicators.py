from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import SHA256_LENGTH, MD5_LENGTH, SHA1_LENGTH, ACTION_PARAM_MAPPING
from MicrosoftDefenderATPManager import MicrosoftDefenderATPManager, MicrosoftDefenderATPError, \
    MicrosoftDefenderATPForbiddenError
from UtilsManager import is_valid_domain, get_entity_original_identifier

PROVIDER_NAME = u'MicrosoftDefenderATP'
SCRIPT_NAME = u'{} - Submit Entity Indicators'.format(PROVIDER_NAME)
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

    action = extract_action_param(siemplify, param_name="Action", input_type=unicode, is_mandatory=True)
    severity = extract_action_param(siemplify, param_name="Severity", input_type=unicode, is_mandatory=True)
    application = extract_action_param(siemplify, param_name="Application", input_type=unicode, is_mandatory=False)
    alert_title = extract_action_param(siemplify, param_name="Indicator Alert Title", input_type=unicode,
                                       is_mandatory=True)
    description = extract_action_param(siemplify, param_name="Description", input_type=unicode, is_mandatory=True)
    recommended_action = extract_action_param(siemplify, param_name="Recommended Action", input_type=unicode,
                                              is_mandatory=False)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_messages = []
    submitted_entities = []
    failed_entities = []
    existing_entities = []
    forbidden_entities = []
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

        existing_indicators = [indicator.indicator_value.lower() for indicator in
                               microsoft_defender_atp.get_entities(entities=[get_entity_original_identifier(entity)
                                                                             for entity in suitable_entities])]

        for entity in suitable_entities:
            siemplify.LOGGER.info(u'Started processing entity {}'.format(entity.identifier))
            entity_identifier = get_entity_original_identifier(entity)
            entity_type = None
            if entity.entity_type == EntityTypes.FILEHASH:
                if len(entity_identifier) == SHA256_LENGTH:
                    entity_type = u"FileSha256"
                elif len(entity_identifier) == MD5_LENGTH:
                    entity_type = u"FileMd5"
                elif len(entity_identifier) == SHA1_LENGTH:
                    entity_type = u"FileSha1"
                else:
                    siemplify.LOGGER.error(u"Not supported hash type. Provide either MD5, SHA-256 or SHA-1.")
                    siemplify.LOGGER.info(u"Finished processing entity {}".format(entity.identifier))
                    continue
            elif entity.entity_type == EntityTypes.ADDRESS:
                entity_type = u"IpAddress"
            elif entity.entity_type == EntityTypes.URL:
                if is_valid_domain(entity_identifier):
                    entity_type = u"DomainName"
                else:
                    entity_type = u"Url"

            if entity_identifier.lower() in existing_indicators:
                existing_entities.append(entity)
            else:
                try:
                    microsoft_defender_atp.submit_entity(entity_identifier=entity_identifier, entity_type=entity_type,
                                                         title=alert_title, action=ACTION_PARAM_MAPPING.get(action),
                                                         application=application, severity=severity,
                                                         description=description, recommended_action=recommended_action)
                    submitted_entities.append(entity)

                except MicrosoftDefenderATPForbiddenError:
                    forbidden_entities.append(entity)
                    siemplify.LOGGER.error(u"An error occurred on entity: {}".format(entity.identifier))
                    siemplify.LOGGER.exception(u"Instance doesn't have enough permissions to submit the entity.")
                except MicrosoftDefenderATPError as e:
                    failed_entities.append(entity)
                    siemplify.LOGGER.error(u"An error occurred on entity: {}".format(entity.identifier))
                    siemplify.LOGGER.exception(e)
            siemplify.LOGGER.info(u"Finished processing entity {}".format(entity.identifier))

        if submitted_entities:
            output_messages.append(u'Successfully submitted the following entities as indicators to Microsoft Defender '
                                   u'ATP: {}'.format(MicrosoftDefenderATPManager.
                                                     convert_list_to_comma_separated_string([entity.identifier
                                                                                             for entity in
                                                                                             submitted_entities])))

        if failed_entities:
            output_messages.append(
                u"Action wasn't able to submit the following entities as indicators to Microsoft Defender "
                u"ATP: {}".format(MicrosoftDefenderATPManager.
                                  convert_list_to_comma_separated_string([entity.identifier
                                                                          for entity in
                                                                          failed_entities])))

        if forbidden_entities:
            output_messages.append(
                u"Instance doesn't have enough permissions to submit for the following entities: {}".format(
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string([entity.identifier
                                                                                        for entity in
                                                                                        forbidden_entities])))

        if existing_entities:
            output_messages.append(
                u"The following entities are already indicators in Microsoft Defender "
                u"ATP: {}".format(MicrosoftDefenderATPManager.
                                  convert_list_to_comma_separated_string([entity.identifier
                                                                          for entity in
                                                                          existing_entities])))

        if not submitted_entities and not existing_entities:
            result_value = False
            if forbidden_entities and not failed_entities:
                raise MicrosoftDefenderATPError(u"none of the indicators were created due to instance permissions, "
                                                u"please check the configuration.")
            elif not forbidden_entities:
                output_messages = [u'None of the provided entities were submitted as indicators to Microsoft '
                                   u'Defender ATP.']

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
