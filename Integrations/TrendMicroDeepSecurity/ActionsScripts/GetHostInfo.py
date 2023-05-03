from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from TrendmicroDeepSecurityManager import TrendmicroManager
from SiemplifyAction import SiemplifyAction
import json

SCRIPT_NAME = "TrendMicro Deep Security - GetHostInfo"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    conf = siemplify.get_configuration('TrendMicroDeepSecurity')
    api_root = conf.get('Api Root')
    api_key = conf.get('Api Secret Key')
    api_version = conf.get('Api Version')
    use_ssl = conf.get("Verify SSL")
    trendmicro_manager = TrendmicroManager(api_root, api_key, api_version, use_ssl)

    entities = []

    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.HOSTNAME and not entity.is_internal:
            try:
                computer_id = trendmicro_manager.get_computer_id_by_name(entity.identifier)
                computer_details = trendmicro_manager.get_computer_info(computer_id)
                siemplify.result.add_json(entity.identifier, json.dumps(computer_details))

                # TODO: enrich? (Meny)
                entities.append(entity.identifier)
            except Exception as e:
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error("An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)

    if entities:
        output_message = "Successfully get computer details. Computers: {0}".format(', '.join([entity for entity in entities]))
    else:
        output_message = "No computer details were found."

    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()