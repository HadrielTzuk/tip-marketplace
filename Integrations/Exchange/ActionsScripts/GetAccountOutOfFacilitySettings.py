from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from ExchangeActions import init_manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, GET_ACCOUNT_OUT_OF_FACILITY_SETTINGS
from SiemplifyDataModel import EntityTypes
from EmailUtils import is_valid_email
from exceptions import UnableToGetValidEmailFromEntity
from TIPCommon import construct_csv

ACTIVE_DIRECTORY_ENRICHMENT_KEY_FOR_MAIL = 'AD_mail_1'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_ACCOUNT_OUT_OF_FACILITY_SETTINGS
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ''
    successful_entities = []
    enrichment_entities = []
    failed_entities = []
    user_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.USER]
    json_results = {}

    try:
        # Create new exchange manager instance
        em = init_manager(siemplify, INTEGRATION_NAME)

        for user_entity in user_entities:
            try:
                siemplify.LOGGER.info('\n\nStarted processing entity: {}'.format(user_entity.identifier))

                # Validate if User Entity is email.
                user_valid_email = user_entity.identifier if is_valid_email(user_entity.identifier) else \
                    user_entity.additional_properties.get(ACTIVE_DIRECTORY_ENRICHMENT_KEY_FOR_MAIL)

                if not user_valid_email:
                    raise UnableToGetValidEmailFromEntity

                user_oof_settings = em.get_oof_settings_for_user(user_valid_email)
                successful_entities.append(user_valid_email)
                enrichment_entities.append(user_entity)

                siemplify.result.add_data_table(title="{} Out of Facility Settings".format(user_entity.identifier),
                                                data_table=construct_csv(user_oof_settings.to_table()))
                json_results[user_entity.identifier] = user_oof_settings.to_json()
                user_entity.additional_properties.update(user_oof_settings.to_enrichment_data())
                user_entity.is_enriched = True
                siemplify.LOGGER.info('Successfully returned OOF settings for {}'.format(user_entity.identifier))
            except Exception as e:
                failed_entities.append(user_valid_email or user_entity.identifier)
                siemplify.LOGGER.error(
                    'Action wasn\'t able to find OOF settings for {}'.format(user_entity.identifier))
                siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info('Finished processing entity: {}'.format(user_entity.identifier))

        if successful_entities:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            siemplify.update_entities(enrichment_entities)
            output_message += '\nSuccessfully returned OOF settings for \n{}'.format('\n'.join(successful_entities))

        if failed_entities:
            output_message += '\nAction wasn\'t able to find OOF settings for \n{}'.format('\n'.join(failed_entities))

        if not successful_entities:
            output_message = 'No entities where processed'
            result = False

    except Exception as e:
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = 'Error executing action {}. Reason: {}'.format(GET_ACCOUNT_OUT_OF_FACILITY_SETTINGS, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('\n----------------- Main - Finished -----------------')
    siemplify.LOGGER.info('Output Message: {}'.format(output_message))
    siemplify.LOGGER.info('Result: {}'.format(result))
    siemplify.LOGGER.info('Status: {}'.format(status))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
