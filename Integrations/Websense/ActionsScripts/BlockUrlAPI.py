from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import *
from WebsenseManager import WebsenseAPIManager
from TIPCommon import extract_configuration_param

INTEGRATION_NAME = 'Websense'


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('Websense')
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             input_type=bool, default_value=False)

    websense_manager = WebsenseAPIManager(conf['ApiRoot'], conf['GatewayUser'], conf['GatewayPassword'], verify_ssl)
    category = siemplify.parameters['CategoryName']
    urls = siemplify.parameters.get('Urls', "").split(",") if siemplify.parameters.get('Urls') else []

    # Build using input parameter or siemplify entities
    if not urls:
        urls = [entity.identifier for entity in siemplify.target_entities if entity.entity_type == EntityTypes.URL]

    blocked_urls = []
    for url in urls:
        result = websense_manager.add_url_to_category(url, category)
        if result:
            blocked_urls.append(url)

    if blocked_urls:
        result_value = 'true'
        output_message = 'Urls:{0} added to category:{1}'.format(blocked_urls, category)
    else:
        output_message = 'No Urls were blocked'
        result_value = 'False'

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
