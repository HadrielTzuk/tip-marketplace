from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from RSAManager import RSAManager
from TIPCommon import extract_configuration_param, construct_csv, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    QUERY_NET_USER_ACTION,
    ATTACHMENT_NAME,
    DEFAULT_HOURS_BACKWARDS,
    DEFAULT_EVENTS_LIMIT
)

SUPPORTED_ENTITY_TYPES = [EntityTypes.USER]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = QUERY_NET_USER_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Configuration
    broker_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Broker API Root")
    broker_username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Broker API Username")
    broker_password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Broker API Password")
    concentrator_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                        param_name="Concentrator API Root")
    concentrator_username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                        param_name="Concentrator API Username")
    concentrator_password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                        param_name="Concentrator API Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    # Parameters
    hours_backwards = extract_action_param(siemplify, param_name="Max Hours Backwards",
                                           default_value=DEFAULT_HOURS_BACKWARDS, input_type=int)
    events_limit = extract_action_param(siemplify, param_name="Max Events To Return",
                                        default_value=DEFAULT_EVENTS_LIMIT, input_type=int)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    json_result = {}
    entities_with_result = []
    failed_entities = []
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    output_message = ''
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        rsa_manager = RSAManager(broker_api_root=broker_api_root, broker_username=broker_username,
                                 broker_password=broker_password, concentrator_api_root=concentrator_api_root,
                                 concentrator_username=concentrator_username,
                                 concentrator_password=concentrator_password, size=events_limit, verify_ssl=verify_ssl)

        for entity in suitable_entities:
            try:
                siemplify.LOGGER.info('\n\nStarted processing entity: {}'.format(entity.identifier))

                events = rsa_manager.get_events_for_user(entity.identifier, hours_backwards)
                if events:
                    json_result[entity.identifier] = [event.to_json() for event in events]
                    siemplify.result.add_entity_table(entity.identifier,
                                                      construct_csv([event.to_csv() for event in events]))

                    siemplify.result.add_entity_attachment(entity.identifier,
                                                           ATTACHMENT_NAME.format(entity.identifier),
                                                           rsa_manager.get_pcap_for_user(entity.identifier,
                                                                                         hours_backwards))
                    entities_with_result.append(entity.identifier)
                    result_value = True
                siemplify.LOGGER.info('Found {} event(s)'.format(len(events)))
                siemplify.LOGGER.info("Finished processing entity: {}".format(entity.identifier))
            except Exception as e:
                failed_entities.append(entity.identifier)
                siemplify.LOGGER.error(
                    'Action was not able to processing entity :  \n {}'.format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if failed_entities:
            output_message += 'Events were not found for the following users: {}.'.format(', '.join(failed_entities))

        if entities_with_result:
            output_message += 'Successfully found events in RSA NetWitness for the following users: {}.'.format(
                ', '.join(entities_with_result))
        else:
            output_message += '\n  No events were found.'

        siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_result))

    except Exception as e:
        output_message = 'Error executing action {}. Reason: {}'.format(QUERY_NET_USER_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
