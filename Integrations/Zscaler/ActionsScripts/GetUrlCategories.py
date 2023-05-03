from SiemplifyUtils import output_handler
from ZscalerManager import ZscalerManager
from SiemplifyAction import SiemplifyAction
from TIPCommon import construct_csv, dict_to_flat
import json


def construct_categories_table(results):
    """
    Build the csv table for the categories
    :param results: {list} List of found categories results
    :return: {list} The csv ready output
    """
    csv_output = []
    for result in results:
        csv_output.append(
            {
                'ID': result.get('id'),
                'Custom Category': result.get('customCategory'),
                'URLS Count': len(result.get('urls'))
            }
        )

    return csv_output


def construct_category_url_table(category_info):
    """
    Build the csv table for the category urls
    :param category_info: {dict} The category info
    :return: {list} The csv ready output
    """
    csv_output = []
    for url in category_info.get('urls', []):
        csv_output.append(
            {
                'URL': url
            }
        )

    return csv_output

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = 'Zscaler - Get URL Categories'
    conf = siemplify.get_configuration('Zscaler')
    cloud_name = conf['Api Root']
    login_id = conf['Login ID']
    api_key = conf['Api Key']
    password = conf['Password']
    verify_ssl = conf.get('Verify SSL', 'False').lower() == 'true'
    zscaler_manager = ZscalerManager(cloud_name, login_id, api_key, password, verify_ssl=verify_ssl, logger=siemplify.LOGGER)

    display_urls = str(siemplify.parameters.get('Display URL', 'False')).lower() == 'true'

    categories = zscaler_manager.list_url_categories()

    if categories:
        json_result = json.dumps(categories)
        siemplify.LOGGER.info("Found {} categories.".format(len(categories)))
        siemplify.LOGGER.info("Adding categories table.")
        siemplify.result.add_data_table('Zscaler Categories', construct_csv(construct_categories_table(categories)))

        if display_urls:
            for category in categories:
                category_id = category.get('id')
                csv_output = construct_csv(construct_category_url_table(category))

                if csv_output:
                    siemplify.LOGGER.info("Adding urls table for category {}.".format(category_id))
                    siemplify.result.add_data_table('{} - URLs'.format(category_id), csv_output)

        output_message = 'Successfully get Zscaler Categories'
        result_value = 'true'

    else:
        json_result = {}
        output_message = 'No results found'
        result_value = 'false'

    siemplify.result.add_result_json(json_result)
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
