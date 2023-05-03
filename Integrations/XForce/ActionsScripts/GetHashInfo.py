from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import add_prefix_to_dict_keys, construct_csv, convert_dict_to_json_result_dict
from XForceManager import XForceManager, XForceNotFoundError, XForceAccessDeniedError
import json

HASH = EntityTypes.FILEHASH
SCRIPT_NAME = "IBM XForce - Get Hash Info"
RISK_MAP = {'high': 3, 'medium': 2, 'low': 1}


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    conf = siemplify.get_configuration('XForce')
    address = conf['Address']
    api_key = conf['Api Key']
    api_password = conf['Api Password']
    verify_ssl = conf['Verify SSL'].lower() == 'true'

    xf_manager = XForceManager(api_key, api_password, address, verify_ssl=verify_ssl)
    threshold = siemplify.parameters.get('Threshold', 'low')

    enriched_entities = []
    csv_results = []
    entities_with_score = {}
    output_message = ''
    is_risk = 'false'
    json_results = {}

    not_found_entities = []
    access_denied = []
    not_enriched_entities = []

    for entity in siemplify.target_entities:
        if entity.entity_type == HASH:
            try:
                report = xf_manager.get_hash_info(entity.identifier)
                if report:
                    json_results[entity.identifier] = report
                    risk_score = report.get('malware', {}).get('risk') or 'low'
                    families_list = report.get('malware', {}).get('origins', {}).get('external', {}).get('family') or []
                    families = '| '.join(str(family) for family in families_list)
                    created = str(report.get('malware', {}).get('created') or '')

                    # Attach report
                    siemplify.result.add_entity_json(entity.identifier, json.dumps(report))

                    # Build csv table
                    csv_results.append({"HASH": entity.identifier, "Created": created, "Risk": str(risk_score), "Families": families})

                    # Enrich - Score and Families (comma separated)
                    enrich_dict = {"Risk": str(risk_score), "Families": families}
                    flat_report = add_prefix_to_dict_keys(enrich_dict, "IBM_XForce")
                    entity.additional_properties.update(flat_report)
                    entity.is_enriched = True

                    threshold_int = RISK_MAP.get(threshold)
                    risk_score_int = RISK_MAP.get(risk_score)
                    if threshold_int < risk_score_int:
                        entity.is_suspicious = True
                        # Add Insight
                        is_risk = 'true'
                        insight_msg = 'IBM XForce - Hash marked as malware'
                        siemplify.add_entity_insight(entity, insight_msg, triggered_by='XForce')

                    entities_with_score.update({entity.identifier: risk_score})
                    enriched_entities.append(entity)

            except XForceNotFoundError as e:
                siemplify.LOGGER.error(u"An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)
                not_found_entities.append(entity.identifier)

            except XForceAccessDeniedError as e:
                siemplify.LOGGER.error(u"An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)
                access_denied.append(entity.identifier)

            except Exception as e:
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error(u"An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)
                not_enriched_entities.append(entity.identifier)

    if csv_results:
        # Add csv table
        siemplify.result.add_data_table("Summary", construct_csv(csv_results))

    if entities_with_score:
        output_message = "The following entities were enriched \n"
        for hash_val, score in entities_with_score.items():
            output_message = u'{0} {1} risk score marked as: {2} \n'.format(output_message, hash_val, score)
        siemplify.update_entities(enriched_entities)

    if not_found_entities:
        output_message += u"The following entities were not found in IBM X-Force: {0} \n".format('\n'.join(not_found_entities))

    if access_denied:
        output_message += u"The following entities were not enriched - Access was denied: {0} \n".format('\n'.join(access_denied))

    if not_enriched_entities:
        output_message += u"The following entities were not enriched - API error: {0} \n".format('\n'.join(not_enriched_entities))

    # add json
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    siemplify.end(output_message, is_risk)


if __name__ == "__main__":
    main()
