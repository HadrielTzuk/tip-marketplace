from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from PassiveTotalManager import PassiveTotal


siemplify = SiemplifyAction()
configuration = siemplify.get_configuration('PassiveTotal')
passive_total = PassiveTotal(user=configuration['Username'], key=configuration['Api_Key'])

whois_dict = passive_total.get_whois_report("google.com")

# In case of error
if whois_dict.get('message'):
    # Print Error
    print whois_dict.get('message')
    whois_dict = None

output_message = "Connection Established" if whois_dict else "Connection Failed"
result_value = True if whois_dict else False
siemplify.end(output_message, result_value)
