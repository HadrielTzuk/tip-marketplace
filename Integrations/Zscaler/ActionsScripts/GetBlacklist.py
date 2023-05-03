from SiemplifyUtils import output_handler
from ZscalerManager import ZscalerManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import construct_csv
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = 'Zscaler - Get Blacklist'
    conf = siemplify.get_configuration('Zscaler')
    cloud_name = conf['Api Root']
    login_id = conf['Login ID']
    api_key = conf['Api Key']
    password = conf['Password']
    verify_ssl = conf.get('Verify SSL', 'False').lower() == 'true'
    zscaler_manager = ZscalerManager(cloud_name, login_id, api_key, password, verify_ssl=verify_ssl, logger=siemplify.LOGGER)

    json_results = {}
    blacklist_dict = zscaler_manager.get_blacklist_items()
    blacklist = blacklist_dict.get('blacklistUrls')

    if blacklist:
        output_message = 'Found {0} Blocked Malicious URLs'.format(len(blacklist))
        csv_output = construct_csv([{'Blacklisted URL': url} for url in blacklist])
        siemplify.result.add_data_table(
            'Blacklist Urls', csv_output)
        json_results = json.dumps(blacklist_dict)
        result_value = ", ".join(blacklist)

    else:
        output_message = 'Found 0 Blocked Malicious URLs'
        result_value = " "

    siemplify.result.add_result_json(json_results)
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
