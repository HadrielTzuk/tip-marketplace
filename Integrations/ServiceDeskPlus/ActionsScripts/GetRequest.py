from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, flat_dict_to_csv
from ServiceDeskPlusManager import ServiceDeskPlusManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('ServiceDeskPlus')
    api_root = conf['Api Root']
    api_key = conf['Api Key']

    service_desk_plus_manager = ServiceDeskPlusManager(api_root, api_key)

    # Parameters
    request_id = siemplify.parameters['Request ID']

    request_info = service_desk_plus_manager.get_request(request_id)

    if request_info:
        # Add csv table
        flat_request = dict_to_flat(request_info)
        csv_output = flat_dict_to_csv(flat_request)
        siemplify.result.add_entity_table(
            'Request {}'.format(request_id), csv_output
        )
        
        output_message = "Request {} was retrieved from ServiceDesk Plus.".format(request_id)
        result_value = 'true'

    else:
        output_message = "Failed to retrieved ServiceDesk Plus request {}.".format(request_id)
        result_value = 'false'

    siemplify.result.add_result_json(request_info or {})
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
