from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from IntezerManager import IntezerManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration("Intezer")
    api_key = conf["Api Key"]
    verify_ssl = conf.get('Verify SSL', 'False').lower() == 'true'

    intezer_manager = IntezerManager(api_key, verify_ssl=verify_ssl)

    # Test connectivity
    siemplify.end("Connected successfully.", 'true')


if __name__ == '__main__':
    main()