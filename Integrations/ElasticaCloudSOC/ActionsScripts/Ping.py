from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ElasticaCloudSOCManager import ElasticaCloudSOCManager

ELASTICA_PROVIDER = 'ElasticaCloudSOC'


@output_handler
def main():
    # Configurations.
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration(ELASTICA_PROVIDER)
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    elastica_manager = ElasticaCloudSOCManager(conf['API Root'],
                                               conf['Key ID'],
                                               conf['Key Secret'],
                                               verify_ssl)

    result_value = elastica_manager.ping()

    if result_value:
        output_message = 'Connection Established.'
    else:
        output_message = 'Connection Failed.'

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()

