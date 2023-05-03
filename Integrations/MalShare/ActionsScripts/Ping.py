from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from MalShareManager import MalShareManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    # Configuration.
    conf = siemplify.get_configuration('MalShare')
    api_key = conf['Api Key']
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    malshare = MalShareManager(api_key, verify_ssl)

    malshare.test_connectivity()

    # If no exception occur - then connection is successful
    siemplify.end("Connected successfully.", 'true')


if __name__ == '__main__':
    main()
