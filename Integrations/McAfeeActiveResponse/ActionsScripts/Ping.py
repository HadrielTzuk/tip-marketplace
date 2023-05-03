from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from McAfeeActiveResponseManager import McAfeeActiveResponseManager

PROVIDER = 'McAfeeActiveResponse'


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration(PROVIDER)

    # The connection is established at the Init function of the class.
    mar_manager = McAfeeActiveResponseManager(conf.get('Broker URLs List').split(',') if conf.get('Broker URLs List')
                                              else [],
                                              conf.get('Broker CA Bundle File Path'),
                                              conf.get('Certificate File Path'),
                                              conf.get('Private Key File Path'))

    siemplify.end('Connection Established.', True)


if __name__ == '__main__':
    main()
