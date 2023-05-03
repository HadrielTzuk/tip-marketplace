from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SymantecICDXManager import SymantecICDXManager
from SiemplifyUtils import dict_to_flat


PROVIDER = "SymantecICDX"
ACTION_NAME = "SymantecICDX - Get Event"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.action_definition_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    verify_ssl = conf.get('Verify SSL').lower() == 'true'
    icdx_manager = SymantecICDXManager(api_root=conf.get('Api Root'),
                                       api_key=conf.get('Api Token'),
                                       verify_ssl=verify_ssl)
    result_value = False

    event_uuid = siemplify.parameters.get('Event UUID')
    event_data = icdx_manager.get_event(event_uuid)

    if event_data:
        siemplify.result.add_result_json(event_data)
        siemplify.result.add_data_table(event_uuid, dict_to_flat(event_data))
        output_message = 'Found event for UUID: {0}'.format(event_uuid)
        result_value = True
    else:
        output_message = 'Not found event for UUID: {0}'.format(event_uuid)

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
