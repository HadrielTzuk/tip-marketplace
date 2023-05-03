from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyDataModel import EntityTypes

from TIPCommon import extract_configuration_param

from McAfeeMvisionEDRManager import McAfeeMvisionEDRManager
from constants import PROVIDER_NAME

SCRIPT_NAME = u"McAfeeMvisionEDR - EnrichEndpoint"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(
        siemplify, provider_name=PROVIDER_NAME, param_name="API Root", input_type=unicode
    )
    username = extract_configuration_param(
        siemplify, provider_name=PROVIDER_NAME, param_name="Username", input_type=unicode
    )
    password = extract_configuration_param(
        siemplify, provider_name=PROVIDER_NAME, param_name="Password", input_type=unicode
    )
    client_id = extract_configuration_param(
        siemplify, provider_name=PROVIDER_NAME, param_name="Client ID", input_type=unicode
    )
    client_secret = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Client Secret",
        input_type=unicode,
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Verify SSL",
        default_value=False,
        input_type=bool,
    )

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    result_value = u'true'
    output_message = u""
    json_results = {}
    status = EXECUTION_STATE_COMPLETED
    enriched_entities = []
    failed_entities = []

    try:
        mvision_edr_manager = McAfeeMvisionEDRManager(
            api_root, username, password, client_id, client_secret, verify_ssl=verify_ssl
        )
        suitable_entities = [
            entity
            for entity in siemplify.target_entities
            if entity.entity_type == EntityTypes.ADDRESS
            or entity.entity_type == EntityTypes.HOSTNAME
        ]

        hosts = mvision_edr_manager.get_hosts()
        for entity in suitable_entities:
            siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
            for host in hosts:
                if entity.identifier.lower() == host.hostname.lower() or entity.identifier in map(lambda item: item.ip,
                                                                                  host.net_interfaces):
                    if entity not in enriched_entities:
                        enrichment_data = host.to_enrichment_data(prefix=u"MMV_EDR")
                        entity.additional_properties.update(enrichment_data)
                        entity.is_enriched = True

                        # JSON result
                        json_results[entity.identifier] = host.to_json()
                        siemplify.result.add_entity_table(entity.identifier, host.to_csv())
                        siemplify.LOGGER.info(
                            u'Successfully enriched the following endpoint from McAfee Mvision EDR {}'.format(
                                entity.identifier))
                        enriched_entities.append(entity)


            if entity not in enriched_entities:
                failed_entities.append(entity)
            siemplify.LOGGER.info(u"Finished processing entity: {}".format(entity.identifier))

    except Exception as e:
        output_message = u"Error executing action {}. Reason: {}".format(SCRIPT_NAME, e)
        siemplify.LOGGER.error(u"Error executing action {}. Reason: {}".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u'false'

    if failed_entities:
        output_message += u"\n\nAction was not able to enrich the following endpoints from McAfee Mvision EDR:\n" + u"{}".format(u'\n'.join([entity.identifier for entity in failed_entities]))

    if enriched_entities:
        siemplify.update_entities(enriched_entities)
        siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
        output_message += u"\n\nSuccessfully enriched the following endpoints from McAfee Mvision EDR:\n" + u"{}".format(
            u'\n'.join([entity.identifier for entity in enriched_entities]))
    else:
        output_message += u"No entities were enriched."
        result_value = u'false'

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
