from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CiscoISEManager import CiscoISEManager
from TIPCommon import dict_to_flat, flat_dict_to_csv, extract_configuration_param, extract_action_param
from SiemplifyDataModel import EntityTypes

INTEGRATION_NAME = u"CiscoISE"


@output_handler
def main():
    # Configuration.
    siemplify = SiemplifyAction()
    siemplify.script_name = u"CiscoISE_EnrichEndpoint"

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             input_type=bool, print_value=True)

    cim = CiscoISEManager(api_root, username, password, verify_ssl)

    # Variables.
    result_value = False
    errors_flag = False
    errors = []

    ip_addresses_entities = [entity for entity in siemplify.target_entities if
                             entity.entity_type == EntityTypes.ADDRESS]

    for ip_address_entity in ip_addresses_entities:
        try:
            mac_address = cim.get_endpoint_mac_by_ip(ip_address_entity.identifier)
            endpoint_data = cim.get_endpoint_by_mac(mac_address)
            if endpoint_data and endpoint_data.get(u'ERSEndPoint'):
                endpoint_data_flat = dict_to_flat(endpoint_data.get(u'ERSEndPoint'))
                # Get enrichment.
                try:
                    enrichment = cim.get_endpoint_enrichment(mac_address)
                    flat_enrichment = dict_to_flat(enrichment)
                    endpoint_data_flat.update(flat_enrichment)
                except Exception as err:
                    siemplify.LOGGER.error(
                        u'Error fetching enrichment for "{0}", Error: {1}'.format(ip_address_entity.identifier,
                                                                                  err.message))
                    siemplify.LOGGER.exception(err)

                endpoint_csv = flat_dict_to_csv(endpoint_data_flat)
                siemplify.result.add_entity_table(ip_address_entity.identifier, endpoint_csv)
                ip_address_entity.additional_properties.update(endpoint_data_flat)
                ip_address_entity.is_enriched = True
                result_value = True
        except Exception as err:
            siemplify.LOGGER.error(
                u'Error fetching data for "{0}", ERROR: {1}'.format(ip_address_entity.identifier, err.message))
            siemplify.LOGGER.exception(err)
            errors_flag = True
            errors.append(
                u'Error fetching data for "{0}", ERROR: {1}'.format(ip_address_entity.identifier, err.message))

    if result_value:
        output_message = u"Found data for endpoint."
    else:
        output_message = u"No data found for endpoint."

    if errors_flag:
        output_message = u"{0} \n \n  ERRORS: {1}".format(output_message, u' \n '.join(errors))

    siemplify.update_entities(siemplify.target_entities)

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
