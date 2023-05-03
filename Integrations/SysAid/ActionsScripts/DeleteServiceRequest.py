from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SysAidManager import SysAidManager


PROVIDER = "SysAid"
ACTION_NAME = "SysAid - DeleteServiceRequest"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.action_definition_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    verify_ssl = conf.get('Verify SSL').lower() == 'true'
    sysaid_manager = SysAidManager(server_address=conf.get('Api Root'),
                                           username=conf.get('Username'),
                                           password=conf.get('Password'),
                                           verify_ssl=verify_ssl)

    sr_id = siemplify.parameters.get('Service Request ID')

    sysaid_manager.delete_service_request(sr_id)
    siemplify.end("Successfully delete service request {}.".format(sr_id), 'true')


if __name__ == "__main__":
    main()