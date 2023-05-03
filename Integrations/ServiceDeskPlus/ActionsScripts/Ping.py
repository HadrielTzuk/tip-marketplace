from SiemplifyUtils import output_handler
from ServiceDeskPlusManager import ServiceDeskPlusManager
from SiemplifyAction import SiemplifyAction


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('ServiceDeskPlus')
    api_root = conf['Api Root']
    api_key = conf['Api Key']

    service_desk_plus_manager = ServiceDeskPlusManager(api_root, api_key)
    service_desk_plus_manager.test_connectivity()

    output_message = "Connected Successfully."
    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()