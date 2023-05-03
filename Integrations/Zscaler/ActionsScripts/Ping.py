from SiemplifyUtils import output_handler
from ZscalerManager import ZscalerManager
from SiemplifyAction import SiemplifyAction


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('Zscaler')
    cloud_name = conf['Api Root']
    login_id = conf['Login ID']
    api_key = conf['Api Key']
    password = conf['Password']
    verify_ssl = conf.get('Verify SSL', 'False').lower() == 'true'
    zscaler_manager = ZscalerManager(cloud_name, login_id, api_key, password, verify_ssl=verify_ssl)

    zscaler_manager.test_connectivity()
    output_message = "Connection Established"
    result_value = 'true'

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
