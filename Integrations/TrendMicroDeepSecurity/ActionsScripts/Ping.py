from SiemplifyUtils import output_handler
from TrendmicroDeepSecurityManager import TrendmicroManager
from SiemplifyAction import SiemplifyAction


@output_handler
def main():
    siemplify = SiemplifyAction()

    conf = siemplify.get_configuration('TrendMicroDeepSecurity')
    api_root = conf.get('Api Root')
    api_key = conf.get('Api Secret Key')
    api_version = conf.get('Api Version')
    use_ssl = conf.get("Verify SSL")
    trendmicro_manager = TrendmicroManager(api_root, api_key, api_version, use_ssl)

    trendmicro_manager.test_connectivity()

    siemplify.end("Connection Established", 'true')


if __name__ == "__main__":
    main()