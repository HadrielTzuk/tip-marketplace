from SiemplifyUtils import output_handler
from ShodanManager import ShodanManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import flat_dict_to_csv
from SiemplifyDataModel import EntityTypes
import json


@output_handler
def main():
    siemplify = SiemplifyAction()

    conf = siemplify.get_configuration('Shodan')
    verify_ssl = conf.get('Verify SSL', 'False').lower() == 'true'
    api_key = conf.get('API key', "")
    shodan = ShodanManager(api_key, verify_ssl=verify_ssl)

    ips_list = []
    json_results = {}
    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.ADDRESS:
            ips_list.append(entity.identifier)
    # Convert ips list to string
    ips = ",".join(ips_list)

    ips_info = shodan.dns_reverse(ips)
    if ips_info:
        json_results = ips_info
        siemplify.result.add_data_table("Shodan DNS Reverse Report", flat_dict_to_csv(ips_info))
        output_message = "Successfully look up hostnames that have been defined for the following IP addresses: {0} \n".format('\n'.join(ips_list))
        result_value = json.dumps(ips_info)
    else:
        output_message = "Failed to look up hostnames that have been defined for the following IP addresses: {0} \n".format('\n'.join(ips_list))
        result_value = '{}'

    # add json
    siemplify.result.add_result_json(json_results)
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
