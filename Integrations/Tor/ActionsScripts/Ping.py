from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TorManager import TorManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration("Tor")
    use_ssl = conf.get('Use SSL', 'False')

    if use_ssl.lower() == 'true':
        use_ssl = True
    else:
        use_ssl = False

    tor_manager = TorManager(use_ssl=use_ssl)

    # Test connectivity
    tor_manager.test_connectivity()
    siemplify.end("Connected successfully.", 'true')


if __name__ == '__main__':
    main()