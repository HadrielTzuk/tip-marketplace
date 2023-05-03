from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from Rapid7Manager import Rapid7Manager


SCRIPT_NAME = "Rapid7InsightVm - Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration("Rapid7InsightVm")
    rapid7_manager = Rapid7Manager(
        conf['Api Root'],
        conf['Username'],
        conf['Password'],
        conf.get('Verify SSL', 'false').lower() == 'true'
    )

    rapid7_manager.test_connectivity()

    output_message = 'Successfully connected to {}.'.format(conf['Api Root'])

    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()
