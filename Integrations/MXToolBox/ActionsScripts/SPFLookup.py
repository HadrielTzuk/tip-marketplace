from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import get_domain_from_entity, construct_csv, convert_dict_to_json_result_dict
from MXToolBoxManager import MXToolBoxManager


MXTOOLBOX_PROVIDER = 'MXToolBox'
SCRIPT_NAME = 'MXToolBox_Investigator_SPF_Lookup'
TABLE_HEADER = 'SPF Lookup Results'

@output_handler
def main():
    # Configurations.
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration(MXTOOLBOX_PROVIDER)
    verify_ssl = conf['Verify SSL'].lower() == 'true'

    mx_tool_box_manager = MXToolBoxManager(conf['API Root'], conf['API Key'], verify_ssl)

    # Variables.
    errors = []
    success_entities = []
    failed_entities = []  # In case ip address is not permitted for domain.
    result_value = True
    entity_csv_header = ['Ranges']
    list_for_csv = []
    json_results = {}

    # Parameters.
    sender_ip = siemplify.parameters.get("IP Address")

    domain_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.HOSTNAME or
                       entity.entity_type == EntityTypes.USER or entity.entity_type == EntityTypes.URL]

    for domain_entity in domain_entities:
        try:
            # Get related ips ranges.
            ip_ranges = mx_tool_box_manager.get_spf_ips_list_for_domain(get_domain_from_entity(domain_entity))
            if ip_ranges:
                json_results[domain_entity.identifier] = ip_ranges
                list_for_csv.append({"Domain/IP": domain_entity.identifier, "SPF domains list": " | ".join(ip_ranges)})
            for ip_range in ip_ranges:
                if mx_tool_box_manager.is_address_in_network_range(sender_ip, ip_range):
                    success_entities.append(domain_entity)
                    domain_entity.additional_properties.update({'MX_SPF Check': 'IP is authorized, in range {0}'.format(
                        ip_range
                    )})
                    domain_entities.is_enriched = True
                    break
            else:
                failed_entities.append(domain_entity)
                domain_entity.additional_properties.update({'MX_SPF Check': 'IP is not authorized sender.'})
                domain_entity.is_suspicious = True
                domain_entity.is_enriched = True
                result_value = False

            if ip_ranges:
                entity_csv_header.extend(ip_ranges)
                siemplify.result.add_entity_table(domain_entity.identifier, entity_csv_header)

        except Exception as e:
            # An error occurred - skip entity and continue
            error_message = "An error occurred on entity: {}.\n{}.".format(domain_entity.identifier, str(e))
            siemplify.LOGGER.error(error_message)
            siemplify.LOGGER.exception(e)
            errors.append(error_message)

    # Make success entities unique list.
    success_entities = list(set(success_entities))

    if list_for_csv:
        siemplify.result.add_data_table(TABLE_HEADER, construct_csv(list_for_csv))

    if success_entities or failed_entities:
        output_message = "{0} is authorized mail sender for {1}".format(
            sender_ip,
            ",".join([entity.identifier for entity in success_entities]))
    else:
        output_message = 'Not found data for target entities.'

    if errors:
        output_message = "{0}  \n \n Errors: \n {1}".format(output_message, " \n ".join(errors))

    siemplify.update_entities(domain_entities)
    # add json
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
