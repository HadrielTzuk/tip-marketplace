from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SEPManager import SEP14Manager
from TIPCommon import extract_configuration_param


INTEGRATION_NAME = "SEP"

@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('SEP')
    username = conf["Username"]
    password = conf["Password"]
    domain = conf["Domain"]
    url = conf["Api Root"]
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             input_type=bool, default_value=False)
    sep_manager = SEP14Manager(url, username, password, domain, verify_ssl=verify_ssl)

    # If no exception occur - then connection is successful
    output_message = "Connected successfully to {url}.".format(
        url=url
    )
    siemplify.end(output_message, True)


if __name__ == '__main__':
    main()
