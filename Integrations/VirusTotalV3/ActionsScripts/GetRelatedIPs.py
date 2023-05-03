from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, extract_action_param
from VirusTotalManager import VirusTotalManager
from constants import PROVIDER_NAME, INTEGRATION_NAME, GET_RELATED_IPS_SCRIPT_NAME, DEFAULT_RELATED_IPS_LIMIT, \
    RELATED_RESULTS_TYPE
from exceptions import VirusTotalLimitReachedException
from UtilsManager import prepare_entity_for_manager


SUPPORTED_ENTITIES = [EntityTypes.FILEHASH, EntityTypes.URL, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_RELATED_IPS_SCRIPT_NAME

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool)
    # Parameters
    results = extract_action_param(siemplify, param_name="Results", default_value=RELATED_RESULTS_TYPE.get("combined"),
                                   print_value=False)
    max_returned_ips = extract_action_param(siemplify, param_name="Max IPs To Return", input_type=int,
                                            default_value=DEFAULT_RELATED_IPS_LIMIT)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    ips = {} if results == RELATED_RESULTS_TYPE.get("per_entity") else []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITIES]

    request_items = [
        {
            'url_id': 'files',
            'url_type': 'contacted_ips',
            'parser_method': 'get_ip_relation',
            'entity_types': [EntityTypes.FILEHASH],
            'name': 'related contacted ips'
        },
        {
            'url_id': 'files',
            'url_type': 'embedded_ips',
            'parser_method': 'get_ip_relation',
            'entity_types': [EntityTypes.FILEHASH],
            'name': 'related embedded ips'
        },
        {
            'url_id': 'urls',
            'url_type': 'contacted_ips',
            'parser_method': 'get_ip_relation',
            'entity_types': [EntityTypes.URL],
            'name': 'related ips'
        },
        {
            'url_id': 'domains',
            'url_type': 'resolutions',
            'parser_method': 'get_ip_relation',
            'entity_types': [EntityTypes.HOSTNAME],
            'name': 'related ips'
        }
    ]

    try:
        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        try:
            for entity in suitable_entities:
                siemplify.LOGGER.info("\nStarted processing entity: {}".format(entity.identifier))

                for data in request_items:
                    if entity.entity_type not in data.get('entity_types'):
                        continue

                    identifier = prepare_entity_for_manager(entity)

                    try:
                        related_items = manager.get_related_items(
                            url_id=data.get('url_id'),
                            entity=identifier,
                            url_type=data.get('url_type'),
                            parser_method=data.get('parser_method'),
                            limit=max_returned_ips
                        )

                        if related_items:
                            if results == RELATED_RESULTS_TYPE.get("per_entity"):
                                ips[entity.identifier] = list(set([related_item.ip.replace(identifier, "")
                                                                   for related_item in related_items]))
                            else:
                                ips.extend([related_item.ip.replace(identifier, "") for related_item in related_items])
                                ips = list(set(ips))

                                if len(ips) >= max_returned_ips:
                                    raise VirusTotalLimitReachedException("Related IPs count reached to maximum limit")
                        else:
                            siemplify.LOGGER.error(f"No {data.get('name')} were found for {entity.identifier}")

                    except VirusTotalLimitReachedException:
                        raise
                    except Exception as err:
                        siemplify.LOGGER.error(f"Failed processing entities: {entity.identifier}")
                        siemplify.LOGGER.exception(err)

                siemplify.LOGGER.info("Finished processing entity {}\n".format(entity.identifier))

        except VirusTotalLimitReachedException as err:
            siemplify.LOGGER.info(err)

        if ips:
            if results == RELATED_RESULTS_TYPE.get("per_entity"):
                siemplify.result.add_result_json({"EntityResults": convert_dict_to_json_result_dict(ips)})
            else:
                siemplify.result.add_result_json({"ips": ips[:max_returned_ips]})

            output_message += "Successfully returned related IPs to the provided entities from {}." \
                .format(PROVIDER_NAME)
        else:
            output_message += "No related IPs were found to the provided entities from {}.".format(PROVIDER_NAME)
            result_value = False

    except Exception as err:
        output_message = "Error executing action “Get Related IPs”. Reason: {}".format(err)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
