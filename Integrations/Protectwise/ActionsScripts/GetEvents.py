from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from ProtectwiseManager import ProtectwiseManager
from SiemplifyUtils import dict_to_flat, convert_datetime_to_unix_time, utc_now
import datetime
import json

@output_handler
def main():
    siemplify = SiemplifyAction()

    configurations = siemplify.get_configuration('Protectwise')
    email = configurations['Email']
    password = configurations['Password']

    time_delta = int(siemplify.parameters['Timeframe (hours)'])

    # Get time frame in unixtime
    end_time = utc_now()
    start_time = utc_now() - datetime.timedelta(hours=time_delta)

    end_time = convert_datetime_to_unix_time(end_time)
    start_time = convert_datetime_to_unix_time(start_time)

    protectwise_manager = ProtectwiseManager(email, password)

    entities_with_events = []

    # All events list - for returning events json as result
    all_events = []

    for entity in siemplify.target_entities:
        results = None

        if entity.entity_type == EntityTypes.ADDRESS:
            results = protectwise_manager.get_ip_reputation(entity.identifier,
                                                            start_time,
                                                            end_time)

        if results:
            if results.get('threat') and results['threat']['events']['count']['total'] :
                # There are events - get their data and attach as csv
                entities_with_events.append(entity.identifier)
                events_info = []

                for event in results['threat']['events']['top']:
                    events_info.append(dict_to_flat(event['_original']))

                all_events.append(events_info)

                csv_output = protectwise_manager.construct_csv(events_info)

                siemplify.result.add_entity_table(entity.identifier,
                                                  csv_output)

    if entities_with_events:
        output_message = 'Successfully found events for the following entities: \n' + '\n'.join(
            entities_with_events)
    else:
        output_message = "No events were found."

    siemplify.end(output_message, json.dumps(all_events))



if __name__ == '__main__':
    main()
