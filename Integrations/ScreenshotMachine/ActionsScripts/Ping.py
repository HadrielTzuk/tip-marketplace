from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScreenshotMachineManager import ScreenshotMachineManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration("ScreenshotMachine")
    api_key = conf.get('API Key')
    use_ssl = conf.get('Use SSL', 'False').lower() == 'true'

    screenshot_machine_manager = ScreenshotMachineManager(api_key,
                                                          use_ssl=use_ssl)

    # Test connectivity
    screenshot_machine_manager.test_connectivity()
    siemplify.end("Connected successfully.", 'true')


if __name__ == '__main__':
    main()