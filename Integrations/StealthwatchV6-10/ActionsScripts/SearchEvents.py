from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import utc_now, convert_datetime_to_unix_time, dict_to_flat, construct_csv
from Stealthwatch610Manager import StealthwatchManager, \
    StealthwatchManagerError
import datetime
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Stealthwatch - search events"
    configurations = siemplify.get_configuration('StealthwatchV6-10')
    server_address = configurations['Api Root']
    username = configurations['Username']
    password = configurations['Password']

    time_delta = int(siemplify.parameters["Timeframe"])

    end_time = utc_now().strftime("%Y-%m-%dT%H:%M:00Z")
    start_time = (utc_now() - datetime.timedelta(hours=time_delta)). \
        strftime("%Y-%m-%dT%H:%M:00Z")

    stealthwatch_manager = StealthwatchManager(server_address, username,
                                               password)

    enriched_entities = []

    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.ADDRESS:
            siemplify.LOGGER.info("Searching events for {}".format(entity.identifier))
            # Get the domain id of the entity
            domain_id = stealthwatch_manager.get_domain_id_by_ip(
                entity.identifier)

            if domain_id:
                results = []

                search_id = stealthwatch_manager.search_events(
                    domain_id,
                    start_time,
                    end_time,
                    src_ip=entity.identifier
                )
                siemplify.LOGGER.info("Search id for source ip: {}".format(search_id))

                if search_id:
                    results = stealthwatch_manager.get_events_search_results(
                        domain_id,
                        search_id
                    )
                search_id = stealthwatch_manager.search_events(
                    domain_id,
                    start_time,
                    end_time,
                    dst_ip=entity.identifier
                )

                siemplify.LOGGER.info(
                    "Search id for dest ip: {}".format(search_id))

                if search_id:
                    results.extend(stealthwatch_manager.get_events_search_results(
                        domain_id,
                        search_id
                    ))

                siemplify.LOGGER.info("Found {} results.".format(len(results)))

                if results:
                    # Attach all data as JSON
                    siemplify.result.add_json("{} - Events".format(
                        entity.identifier,
                    ), json.dumps(results))

                    csv_output = construct_csv(map(dict_to_flat, results))
                    siemplify.result.add_entity_table(
                        "{} - Security Event Details".format(
                            entity.identifier), csv_output)

                    enriched_entities.append(entity)

    if enriched_entities:
        entities_names = [entity.identifier for entity in
                          enriched_entities]

        output_message = 'Security events were found for the following entities:\n' + '\n'.join(
            entities_names)

        siemplify.end(output_message, 'true')

    else:
        output_message = 'No events were found.'
        # No events found and action is completed
        siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()
