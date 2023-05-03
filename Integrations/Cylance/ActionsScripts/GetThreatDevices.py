from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from CylanceManager import CylanceManager
from SiemplifyUtils import dict_to_flat, flat_dict_to_csv, add_prefix_to_dict, convert_dict_to_json_result_dict
import json

SCRIPT_NAME = "Cylance - GetThreatDevices"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration('Cylance')

    server_address = conf['Server Address']
    application_secret = conf['Application Secret']
    application_id = conf['Application ID']
    tenant_identifier = conf['Tenant Identifier']

    cm = CylanceManager(server_address, application_id, application_secret,
                        tenant_identifier)

    affected_entities = []
    json_results = {}

    for entity in siemplify.target_entities:
        try:
            if entity.entity_type == EntityTypes.FILEHASH:
                threats = cm.get_threat_devices(entity.identifier)
                json_results[entity.identifier] = threats

                if threats:
                    threats = map(dict_to_flat, threats)
                    csv_output = cm.construct_csv(threats)

                    siemplify.result.add_entity_table(
                        'Cylance Threats - {}'.format(entity.identifier),
                        csv_output)
                    affected_entities.append(entity)

        except Exception as e:
            # An error occurred - skip entity and continue
            siemplify.LOGGER.error(
                "An error occurred on entity: {}.\n{}.".format(
                    entity.identifier, str(e)
                ))
            siemplify.LOGGER._log.exception(e)

    if affected_entities:
        entities_names = [entity.identifier for entity in affected_entities]

        output_message = 'Threats were found for the following entites:\n' + '\n'.join(
            entities_names)
    else:
        output_message = 'No threats were found.'

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()
