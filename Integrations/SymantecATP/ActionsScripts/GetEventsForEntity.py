from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SymantecATPManager import SymantecATPManager
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import dict_to_flat, flat_dict_to_csv
from TIPCommon import construct_csv
import arrow

ATP_PROVIDER = 'SymantecATP'
RESULT_TABLE_NAME = "Command IDs"
ACTION_NAME = "SymantecATP_Get Events For Entity."
SUPPORTED_ENTITY_TYPES = [EntityTypes.USER, EntityTypes.HOSTNAME, EntityTypes.ADDRESS]

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(ATP_PROVIDER)
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    atp_manager = SymantecATPManager(conf.get('API Root'), conf.get('Client ID'), conf.get('Client Secret'), verify_ssl)

    result_value = False
    errors = []
    success_entities = []
    events_amount = 0
    search_field = ""
    
    # Parameters.
    minutes_back = int(siemplify.parameters.get('Minutes Back To Fetch'))

    target_entities = [
            entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES
        ]
    
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")  
    for entity in target_entities:
        try:
            siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
            # Create arrow time object.
            time_object = arrow.now().shift(minutes=-minutes_back)
            
            
            if entity.entity_type == EntityTypes.ADDRESS:
                search_field = "device_ip"
            
            if entity.entity_type == EntityTypes.HOSTNAME:
                search_field = "device_name"
                
            if entity.entity_type == EntityTypes.USER:
                search_field = "user_name"
       
            result_events = atp_manager.get_event_for_entity_since(search_field, entity.identifier, time_object)
            if result_events:
                events_amount += len(result_events)
                query_result = map(dict_to_flat, result_events)
                csv_result = construct_csv(query_result)
                siemplify.result.add_entity_table(entity.identifier, csv_result)
                
                success_entities.append(entity)
                result_value = True
                siemplify.LOGGER.info(u"Finished processing entity {}".format(entity.identifier))
                
        except Exception as err:
            error_message = 'Error fetching events "{0}", Error: {1}'.format(entity.identifier, unicode(err))
            siemplify.LOGGER.error(error_message)
            siemplify.LOGGER.exception(err)
            errors.append(error_message)

    if result_value:
        output_message = 'Found events for {0}.'.format(','.join([entity.identifier for entity in success_entities]))
    else:
        output_message = 'No events found for target entities.'

    # Attach errors if exists.
    if errors:
        output_message = "{0},\n\nERRORS:\n{1}".format(output_message, ' \n '.join(errors))

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  events_amount: {}\n output_message: {}".format(events_amount, output_message))
   
    siemplify.update_entities(success_entities)
    siemplify.end(output_message, events_amount)


if __name__ == "__main__":
    main()
