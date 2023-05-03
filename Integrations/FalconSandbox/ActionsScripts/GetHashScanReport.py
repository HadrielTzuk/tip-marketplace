from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, add_prefix_to_dict_keys, convert_dict_to_json_result_dict
from FalconSandboxManager import FalconSandboxManager, ENVIRONMENTS
import json
import base64

SCRIPT_NAME = "Falcon Sandbox - EnrichEntities"
ENRICHMENT_REPORT_KEYS = ['environment_id', 'threat_score', 'threat_level',
                          'total_processes', 'size', 'job_id', 'vx_family',
                          'interesting', 'sha256', 'sha512', 'imphash',
                          'total_network_connections', 'av_detect', 'md5',
                          'total_signatures', 'sha1', 'type',
                          'environment_description', 'verdict']

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("================= Main - Param Init =================")

    configurations = siemplify.get_configuration('FalconSandbox')
    server_address = configurations['Api Root']
    key = configurations['Api Key']
    threshold = float(configurations['Threshold'])

    falcon_manager = FalconSandboxManager(server_address, key)
    siemplify.LOGGER.info("Connected to Hybrid Analysis")

    enriched_entities = []
    max_threat_score = 0

    json_results = {}
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    for entity in siemplify.target_entities:
        siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
        if entity.entity_type == EntityTypes.FILEHASH:
            is_enriched = False

            # Fetch report for each available environment
            for env_id in ENVIRONMENTS.keys():
                try:
                    siemplify.LOGGER.info("Fetching reports for environment: {}".format(ENVIRONMENTS[env_id]))

                    reports = falcon_manager.get_scan_info(entity.identifier,
                                                           env_id)
                    json_results[entity.identifier] = reports
                    siemplify.LOGGER.info("Found {} reports.".format(len(reports)))

                    for index, report in enumerate(reports['scan_info'], 1):
                        threat_score = report['threat_score']
                        max_threat_score = max(threat_score, max_threat_score)

                        siemplify.LOGGER.info(
                            "Threat Score: {}".format(threat_score))

                        siemplify.LOGGER.info("Attaching JSON report")
                        siemplify.result.add_json(
                            "{} - {}".format(entity.identifier, index),
                            json.dumps(report))

                        siemplify.LOGGER.info("Enriching entity {}.".format(entity.identifier))
                        enrichment_data = {key: report[key] for key in
                                           ENRICHMENT_REPORT_KEYS}

                        flat_enrichment_data = dict_to_flat(enrichment_data)
                        flat_enrichment_data = add_prefix_to_dict_keys(
                            flat_enrichment_data,
                            index)
                        flat_enrichment_data = add_prefix_to_dict_keys(
                            flat_enrichment_data,
                            "Falcon")

                        entity.additional_properties.update(
                            flat_enrichment_data)
                        is_enriched = True

                        try:
                            mist_report_name, misp_report = falcon_manager.get_report_by_hash(
                                entity.identifier, env_id, type='misp')
                            # Falcon server error with misp json
                            # misp_json_report_name, misp_json_report = falcon_manager.get_report_by_hash(entity.identifier, env_id, type='misp_json')

                            siemplify.result.add_entity_attachment(
                                "{} Report - {}".format(entity.identifier,
                                                        ENVIRONMENTS[env_id]),
                                mist_report_name,
                                base64.b64encode(misp_report)
                            )

                            # siemplify.result.add_entity_attachment(
                            #     entity.identifier,
                            #     "misp_json_report.json",
                            #     base64.b64encode(misp_json_report)
                            # )

                        except Exception as e:
                            siemplify.LOGGER.error(u"Error getting MISP report for environment: {}".format(ENVIRONMENTS[env_id]))
                            siemplify.LOGGER.exception(e)

                except Exception as e:
                    # An error occured while trying to fetch the report -
                    # probably because the hash was not scanned with current
                    # env id. Continue and try with another env id.
                    siemplify.LOGGER.error(u"Error fetching reports for environment: {}".format(ENVIRONMENTS[env_id]))
                    siemplify.LOGGER.exception(e)
                    continue

            if is_enriched:
                if max_threat_score >= threshold:
                    entity.is_suspicious = True

                entity.is_enriched = True

                enriched_entities.append(entity)
        siemplify.LOGGER.info(u"Finished processing entity {0}".format(entity.identifier))
    if enriched_entities:
        entities_names = [entity.identifier for entity in enriched_entities]

        output_message = 'Following entities were enriched by Falcon Sandbox\n' + '\n'.join(
            entities_names)

        siemplify.update_entities(enriched_entities)

    else:
        output_message = 'No entities were enriched.'

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"\n  max_threat_score: {}\n  output_message: {}".format(max_threat_score, output_message))
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.end(output_message, json.dumps(max_threat_score))

if __name__ == '__main__':
    main()
