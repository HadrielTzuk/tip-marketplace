from SiemplifyUtils import output_handler
from CiscoThreatGridManager import CiscoThreatGridManager
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import convert_dict_to_json_result_dict
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = 'CiscoThreatGrid - GetHashAssociatedDomains'

    conf = siemplify.get_configuration('CiscoThreatGrid')
    server_addr = conf['Api Root']
    api_key = conf['Api Key']
    use_ssl = conf['Use SSL'].lower() == 'true'
    cisco_threat_grid = CiscoThreatGridManager(server_addr, api_key, use_ssl)

    enriched_entities = []
    json_results = {}

    for entity in siemplify.target_entities:
        try:
            if entity.entity_type == EntityTypes.FILEHASH:
                associated_domains = cisco_threat_grid.get_associated_network(entity.identifier.lower())['domains']

                if associated_domains:
                    json_results[entity.identifier] = associated_domains
                    csv_output = ['Associated Domain'] + associated_domains
                    siemplify.result.add_entity_table(
                        '{} - Associated Domains'.format(
                            entity.identifier),
                            csv_output)
                    enriched_entities.append(entity)

        except Exception as e:
            # An error occurred - skip entity and continue
            siemplify.LOGGER.error(
                "An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
            siemplify.LOGGER.exception(e)

    if enriched_entities:
        entities_names = [entity.identifier for entity in enriched_entities]
        output_message = 'Cisco Threat Grid - Found associated domains for the following entities\n' + '\n'.join(
            entities_names)

    else:
        output_message = 'No suitable entities found.\n'

    # add json
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()

