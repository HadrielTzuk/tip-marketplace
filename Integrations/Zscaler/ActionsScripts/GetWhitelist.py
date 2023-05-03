from SiemplifyUtils import output_handler
from ZscalerManager import ZscalerManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import construct_csv
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = 'Zscaler - Get Whitelist'
    conf = siemplify.get_configuration('Zscaler')
    cloud_name = conf['Api Root']
    login_id = conf['Login ID']
    api_key = conf['Api Key']
    password = conf['Password']
    verify_ssl = conf.get('Verify SSL', 'False').lower() == 'true'
    zscaler_manager = ZscalerManager(cloud_name, login_id, api_key, password, verify_ssl=verify_ssl, logger=siemplify.LOGGER)

    json_results = {}
    whitelist_dict = zscaler_manager.get_whitelist_items()
    whitelist = whitelist_dict.get('whitelistUrls')

    if whitelist:
        output_message = 'Found {0} Unblocked URLs'.format(len(whitelist))
        result_value = ", ".join(whitelist)

        csv_output = construct_csv(
            [{'Unblocked URL': url} for url in whitelist])
        siemplify.result.add_data_table(
            'Whitelist Urls', csv_output)
        json_results = json.dumps(whitelist_dict)

    else:
        output_message = 'Found 0 Unblocked URLs'
        result_value = " "

    siemplify.result.add_result_json(json_results)
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
