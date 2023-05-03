from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
# Imports
from SiemplifyAction import SiemplifyAction, ScriptResult
from RSAManager import RSA
from SiemplifyUtils import convert_dict_to_json_result_dict
import base64

# Consts.
RSA_PROVIDER = 'RSANetWitness'
HOSTNAME = EntityTypes.HOSTNAME


@output_handler
def main():
    # Variables Definition.
    result_value = False
    entities_with_result = []
    # Configuration.
    siemplify = SiemplifyAction()
    config = siemplify.get_configuration(RSA_PROVIDER)
    # Configuration Parameters.
    concentrator_uri = config['Concentrator Api Root']
    decoder_uri = config['Decoder Api Root']
    username = config['Username']
    password = config['Password']
    verify_ssl = config.get('Verify SSL', 'false').lower() == 'true'

    json_result = {}

    rsa_manager = RSA(concentrator_uri=concentrator_uri,
                      decoder_uri=decoder_uri, username=username,
                      password=password,
                      verify_ssl=verify_ssl)

    scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == HOSTNAME]

    for entity in scope_entities:
        # Get meta.
        csv_output = rsa_manager.get_events_for_domain(entity.identifier, csv_format=True)
        json_output = rsa_manager.get_events_for_domain(entity.identifier)
        # Get pcap data.
        pcap_byte_array = rsa_manager.get_pcap_for_domain(entity.identifier)
        if json_output:
            json_result[entity.identifier] = json_output
        if csv_output:
            siemplify.result.add_entity_table(entity.identifier, csv_output)
            siemplify.result.add_entity_attachment(entity.identifier, '{0}_pcap_file.pcap'.format(entity.identifier),
                                                                                                  base64.b64encode(
                                                                                                      pcap_byte_array))
            entities_with_result.append(entity.identifier)
            result_value = True

    if result_value:
        output_message = 'Found events for entities: {0}'.format(', '.join(entities_with_result))
    else:
        output_message = 'No events were found for entities.'

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_result))
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
