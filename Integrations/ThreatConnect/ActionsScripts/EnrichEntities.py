from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from ThreatConnectManager import ThreatconnectAPI
from SiemplifyUtils import dict_to_flat, add_prefix_to_dict_keys, flat_dict_to_csv, convert_dict_to_json_result_dict

ACTION_NAME = "ThreatConnect_EnrichEntities"

# Available Indicator Types - apiBranch
ADDRESS = 'addresses'
FILE = 'files'
HOST = 'hosts'
URL = 'urls'


# Enrich target entity with threatConnect info and add web link with full details to entity
def enrich_entity(indicator_data, indicator_type, entity, siemplify):
    # Extract weblink
    try:
        link = indicator_data['general'][indicator_type]['webLink']
        siemplify.result.add_entity_link(entity.identifier, link)
    except Exception as e:
        siemplify.LOGGER.error("Cannot extract link from entity data {}".format(entity.identifier))
        siemplify.LOGGER.exception(e)

    # Set risk level
    if indicator_data['general'][indicator_type].get('threatAssessRating', 0) > 1:
        entity.is_suspicious = True

    flat_report = dict_to_flat(indicator_data)
    flat_report = add_prefix_to_dict_keys(flat_report, "TC")
    entity.additional_properties.update(flat_report)
    entity.is_enriched = True
    return True


def add_insight(indicator_data, indicator_type, entity, siemplify):
    insight_msg = ''
    threat_asset_rating = indicator_data.get('general', {}).get(indicator_type, {}).get('threatAssessRating')
    confidence = indicator_data.get('general', {}).get(indicator_type, {}).get('confidence')
    description = indicator_data.get('general', {}).get(indicator_type, {}).get('description')
    tags_list = indicator_data.get('tags') or []
    tags = '| '.join(str(tag) for tag in tags_list)

    insight_msg += u'Threat asset rating: {0}. \n'.format(threat_asset_rating) \
        if threat_asset_rating else u'No threat asset rating. \n'

    insight_msg += u'Confidence: {0}. \n'.format(confidence) \
        if confidence else u'Confidence: 0 \n'

    insight_msg += u'Description: {0}. \n'.format(description) \
        if description else u'No description. \n'

    insight_msg += u'Tags: {0}. \n'.format(tags) \
        if tags else u'No tags. \n'

    siemplify.add_entity_insight(entity, insight_msg, triggered_by='ThreatConnect')


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME

    conf = siemplify.get_configuration('ThreatConnect')
    api_access_id = conf['ApiAccessId']
    api_secret_key = conf['ApiSecretKey']
    api_default_org = conf['ApiDefaultOrg']
    api_base_url = conf['ApiBaseUrl']

    owner_name = siemplify.parameters.get('Owner Name', None)
    enriched_entities = []
    json_results = {}

    threat_connect = ThreatconnectAPI(api_access_id, api_secret_key, api_default_org, api_base_url)
    threat_connect.owner = api_default_org

    for entity in siemplify.target_entities:
        entity_original_identifier = entity.additional_properties.get('OriginalIdentifier', entity.identifier.lower())
        try:
            if entity.entity_type == EntityTypes.ADDRESS:
                indicator_info = threat_connect.get_indicator_info(ADDRESS, entity_original_identifier, owner_name)
                if indicator_info:
                    json_results[entity.identifier] = indicator_info
                    enrich_entity(indicator_info, "address", entity, siemplify)
                    add_insight(indicator_info, "address", entity, siemplify)
                    enriched_entities.append(entity)

            if entity.entity_type == EntityTypes.FILEHASH:
                indicator_info = threat_connect.get_indicator_info(FILE, entity_original_identifier.upper(), owner_name)
                if indicator_info:
                    json_results[entity.identifier] = indicator_info
                    enrich_entity(indicator_info, "file", entity, siemplify)
                    add_insight(indicator_info, "file", entity, siemplify)
                    enriched_entities.append(entity)

            if entity.entity_type == EntityTypes.URL:
                indicator_info = threat_connect.get_indicator_info(URL, entity_original_identifier, owner_name)
                if indicator_info:
                    json_results[entity.identifier] = indicator_info
                    enrich_entity(indicator_info, "url", entity, siemplify)
                    add_insight(indicator_info, "url", entity, siemplify)
                    enriched_entities.append(entity)

            if entity.entity_type == EntityTypes.HOSTNAME:
                indicator_info = threat_connect.get_indicator_info(HOST, entity_original_identifier, owner_name)
                if indicator_info:
                    json_results[entity.identifier] = indicator_info
                    enrich_entity(indicator_info, "host", entity, siemplify)
                    add_insight(indicator_info, "host", entity, siemplify)
                    enriched_entities.append(entity)

        except Exception as e:
            siemplify.LOGGER.error("Error enriching entity {}".format(entity.identifier))
            siemplify.LOGGER.exception(e)

    if enriched_entities:
        output_message = 'Following entities were enriched by ThreatConnect. \n{0}'.format(enriched_entities)
        result_value = 'true'
        siemplify.update_entities(enriched_entities)
    else:
        output_message = 'No entities were enriched.'
        result_value = 'false'

    # add json
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()