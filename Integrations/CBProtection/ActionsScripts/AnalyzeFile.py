from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from CarbonBlackProtectionManager import CBProtectionManager, CBProtectionManagerException
from SiemplifyUtils import convert_dict_to_json_result_dict
import json

IS_MALICIOUS_ADDITIONAL_KEY = "is_malicious"


@output_handler
def main():
    siemplify = SiemplifyAction()
    configurations = siemplify.get_configuration('CBProtection')
    server_addr = configurations['Api Root']
    api_key = configurations['Api Key']

    cb_protection = CBProtectionManager(server_addr, api_key)

    connector_name = siemplify.parameters.get('Connector Name')
    priority = siemplify.parameters.get('Priority', 0)
    timeout = int(siemplify.parameters.get('Timeout', 120))
    connector_id = cb_protection.get_connector_by_name(connector_name).id

    enriched_entities = []
    json_result = {}
    errors = ""

    for entity in siemplify.target_entities:
        try:
            if entity.entity_type == EntityTypes.FILEHASH:
                if len(entity.identifier) == 32:
                    analysis = cb_protection.analyze_file(entity.identifier,
                                                          connector_id,
                                                          priority, wait=True,
                                                          timeout=timeout)

                    if cb_protection.is_file_malicious(analysis.get('id')) or \
                            cb_protection.is_file_suspicious(analysis.get('id')):
                        entity.is_suspicious = True
                        analysis[IS_MALICIOUS_ADDITIONAL_KEY] = True
                    else:
                        analysis[IS_MALICIOUS_ADDITIONAL_KEY] = False

                    json_result[entity.identifier] = analysis
                    enriched_entities.append(entity)

        except Exception as e:
            errors += "Unable to analyze file {0}: \n{1}\n".format(
                entity.identifier, e.message)
            continue

    if enriched_entities:
        entities_names = [entity.identifier for entity in enriched_entities]
        output_message = 'Carbon Black Protection - Analyzes the followng files:\n' + '\n'.join(
            entities_names)
        output_message += errors
        siemplify.update_entities(enriched_entities)

    else:
        output_message = 'Carbon Black Protection - No files were analysed.\n'
        output_message += errors

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_result))
    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()
