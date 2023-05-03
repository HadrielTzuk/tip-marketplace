from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import construct_csv, dict_to_flat
from PortnoxManager import PortnoxManager


SCRIPT_NAME = "Portnox - GetServices"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration("Portnox")
    api_root = conf['Api Root']
    username = conf['Username']
    password = conf['Password']
    use_ssl = str(conf.get('Verify SSL', 'False')).lower() == 'true'
    portnox_manager = PortnoxManager(api_root, username, password, use_ssl)

    enriched_entities = []

    for entity in siemplify.target_entities:
        try:
            device = None

            if entity.entity_type == EntityTypes.ADDRESS:
                device = portnox_manager.search_device('ip', entity.identifier)

            elif entity.entity_type == EntityTypes.MACADDRESS:
                device = portnox_manager.search_device('macAddress', entity.identifier)

            if device:
                device_id = device["id"]
                locations = portnox_manager.get_device_locations(device_id)

                if locations:
                    for location in locations:
                        # Remove not relevant nested data
                        if 'portIds' in location:
                            del location['portIds']

                    csv_output = construct_csv(locations)

                    siemplify.result.add_entity_table(
                        '{} - Locations'.format(
                            entity.identifier),
                        csv_output)

                    enriched_entities.append(entity)

        except Exception as e:
            # An error occurred - skip entity and continue
            siemplify.LOGGER.error(
                "An error occurred on entity: {}.\n{}.".format(
                    entity.identifier, str(e)
                ))

    if enriched_entities:
        entities_names = [entity.identifier for entity in enriched_entities]

        output_message = 'Locations were found for the following entities:\n' + '\n'.join(
            entities_names)

        siemplify.update_entities(enriched_entities)

    else:
        output_message = 'No locations were found.'

    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()
