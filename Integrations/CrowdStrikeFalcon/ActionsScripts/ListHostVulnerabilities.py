from CrowdStrikeManager import CrowdStrikeManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv, string_to_multi_value
from utils import get_entity_original_identifier
from exceptions import CrowdStrikeFalconValidatorException
from datamodels import VulnerabilityList
from constants import (
    INTEGRATION_NAME,
    LIST_HOST_VULNERABILITIES_SCRIPT_NAME,
    API_ROOT_DEFAULT,
    SEVERITY_POSSIBLE_VALUES
)

ENTITIES_MAPPER = {
    EntityTypes.ADDRESS: 'local_ip',
    EntityTypes.HOSTNAME: 'starts_with_name'
}

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_HOST_VULNERABILITIES_SCRIPT_NAME
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    successful_entities, failed_entities, json_results = [], [], {}
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in ENTITIES_MAPPER.keys()]

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           default_value=API_ROOT_DEFAULT)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client API ID')
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name='Client API Secret')
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                          input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    limit = extract_action_param(siemplify, param_name='Max Vulnerabilities To Return', input_type=int, print_value=True)
    create_insight = extract_action_param(siemplify, param_name='Create Insight', default_value=True, print_value=True,
                                          input_type=bool)
    severity = extract_action_param(siemplify, param_name='Severity Filter', print_value=True)
    severity = string_to_multi_value((severity or '').upper())

    try:
        if not all(item in SEVERITY_POSSIBLE_VALUES for item in severity):
            raise CrowdStrikeFalconValidatorException(
                f"Invalid value provided in the 'Severity Filter parameter. Possible values: "
                f"{', '.join(SEVERITY_POSSIBLE_VALUES)}'")

        manager = CrowdStrikeManager(client_id=client_id, client_secret=client_secret, use_ssl=use_ssl,
                                     api_root=api_root, force_check_connectivity=True)
        for entity in suitable_entities:
            remediations, remediation_ids = {}, []
            entity_identifier = get_entity_original_identifier(entity)
            try:
                params = {
                    ENTITIES_MAPPER[entity.entity_type]: entity_identifier
                }
                device_ids = manager.search_device_ids(**params)

                if not device_ids:
                    siemplify.LOGGER.info(f'No device found for entity {entity_identifier}. Skipping.')
                    failed_entities.append(entity_identifier)
                    continue

                vulnerability_ids, total = manager.get_vulnerability_ids(aid=device_ids[0], severity=severity,
                                                                         limit=limit)

                if not vulnerability_ids:
                    siemplify.LOGGER.info(f'No Vulnerability ids found for entity {entity_identifier}. Skipping.')
                    failed_entities.append(entity_identifier)
                    continue

                vulnerabilities = manager.get_vulnerabilities(vulnerability_ids)
                for vulnerability in vulnerabilities:
                    remediation_ids.extend(vulnerability.ids)

                if remediation_ids:
                    siemplify.LOGGER.info(f'There are {len(remediation_ids)} remediation ids for entity '
                                          f'{entity_identifier}.')
                    remediations = manager.get_remediation_details(ids=set(remediation_ids))
                vulnerability_list = VulnerabilityList(vulnerabilities, remediations, total)
                json_results[entity_identifier] = vulnerability_list.to_json()

                siemplify.result.add_data_table(
                    f"{entity_identifier}",
                    construct_csv([vulnerability.to_csv() for vulnerability in vulnerability_list.vulnerabilities])
                )
                if create_insight:
                    siemplify.add_entity_insight(entity, vulnerability_list.to_insight())
                successful_entities.append(entity_identifier)
            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error(f"An error occurred for entity: {entity_identifier}")
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message = f'Successfully retrieved vulnerabilities for the following hosts: ' \
                             f'{", ".join(successful_entities)}\n'

            if failed_entities:
                output_message += f'No vulnerabilities were found for the following hosts: ' \
                                  f'{", ".join(failed_entities)}\n'
        else:
            result_value = False
            output_message = 'No vulnerabilities were found.'

        if json_results:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    except Exception as e:
        output_message = f"Error executing action '{LIST_HOST_VULNERABILITIES_SCRIPT_NAME}'. Reason: {e}"
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
