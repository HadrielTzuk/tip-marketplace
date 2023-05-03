from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from XForceManager import XForceManager
from SiemplifyUtils import construct_csv
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('XForce')
    address = conf['Address']
    api_key = conf['Api Key']
    api_password = conf['Api Password']
    verify_ssl = conf['Verify SSL'].lower() == 'true'
    xf_manager = XForceManager(api_key, api_password, address, verify_ssl=verify_ssl)

    # Category options:
    # Spam, Anonymisation Services, Scanning IPs, Dynamic IPs, Malware, Bots, Botnet Command and Control Server
    category = siemplify.parameters['Category']
    json_results = {}

    ips = xf_manager.get_ip_by_category(category)
    if ips:
        json_results = json.dumps(ips)
        ips_csv = construct_csv(ips)
        siemplify.result.add_data_table(u'IPS in {0}'.format(category), ips_csv)

        output_message = u"{0} retrieved {1} IPs".format(category, len(ips))
        result_value = "true"
    else:
        output_message = u"Failed to retrieved the IPs that are in {0}.".format(category)
        result_value = "false"

    siemplify.result.add_result_json(json_results)

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()