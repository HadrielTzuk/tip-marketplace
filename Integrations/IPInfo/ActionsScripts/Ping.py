from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from IPInfoManager import IPInfoManager

ACTION_NAME = "IPInfo Ping"
PROVIDER = 'IPInfo'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    ipinfo_manager = IPInfoManager(conf['API Root'], conf['Token'], verify_ssl)

    siemplify.end("Connection Established.", ipinfo_manager.ping())


if __name__ == "__main__":
    main()
