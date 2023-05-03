from SiemplifyAction import SiemplifyAction
from OktaManager import OktaManager

PROVIDER = "Okta"

def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration(PROVIDER)
    okta = OktaManager(api_root=conf['Api Root'], api_token=conf['Api Token'],
                       verify_ssl=conf['Verify SSL'].lower() == 'true')
    output_message = ""
    try:
        success = okta.test_connectivity()
        #if success:
        output_message = "Connection Established Successfully"
        #else:
    except Exception as err:
        raise Exception("Connection Failed: " + err.message)
    siemplify.end(output_message, success)

if __name__ == '__main__':
    main()