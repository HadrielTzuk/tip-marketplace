from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from ThreatConnectManager import ThreatconnectAPI

@output_handler
def main():
    siemplify = SiemplifyAction()

    conf = siemplify.get_configuration('ThreatConnect')
    api_access_id = conf['ApiAccessId']
    api_secret_key = conf['ApiSecretKey']
    api_default_org = conf['ApiDefaultOrg']
    api_base_url = conf['ApiBaseUrl']
    
    threat_connect = ThreatconnectAPI(api_access_id, api_secret_key, api_default_org, api_base_url)
    threat_connect.owner = api_default_org

    r = threat_connect.test_connectivity()
    
    if r:
        output_message = "Connection Established"
        result_value = 'true'
    else:
        output_message = "Connection Failed"
        result_value = 'false'
    
    siemplify.end(output_message, result_value)
    
    
if __name__ == '__main__':
    main()