from SiemplifyUtils import output_handler
from TrendmicroDeepSecurityManager import TrendmicroManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import construct_csv


@output_handler
def main():
    siemplify = SiemplifyAction()

    conf = siemplify.get_configuration('TrendMicroDeepSecurity')
    api_root = conf.get('Api Root')
    api_key = conf.get('Api Secret Key')
    api_version = conf.get('Api Version')
    use_ssl = conf.get("Verify SSL")
    trendmicro_manager = TrendmicroManager(api_root, api_key, api_version, use_ssl)

    result_value = 'false'
    output_message = 'No security profiles were found.'

    policies_list = trendmicro_manager.get_all_security_profiles()

    if policies_list:
        # Build csv table
        csv_results = trendmicro_manager.build_csv(policies_list)
        if csv_results:
            siemplify.result.add_data_table("Security Profiles", construct_csv(csv_results))
            result_value = 'true'
            output_message = 'Successfully retrieved {0} security profiles'.format(len(policies_list))

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()