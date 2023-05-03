from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
# Imports
from PhishingInitiativeManager import PhishingInitiativeManager
from SiemplifyAction import SiemplifyAction

# Consts
DUMMY_URL = 'http://www.antiphishing.org/'

@output_handler
def main():
    siemplify = SiemplifyAction()
    # Configuration.
    conf = siemplify.get_configuration('PhishingInitiative')
    api_root = conf['Api Root']
    api_token = conf['Api Token']
    phishing_initiative = PhishingInitiativeManager(api_root, api_token)

    res = phishing_initiative.get_url_info(DUMMY_URL)

    if res:
        output_message = "Connection Established."
        result_value = True
    else:
        output_message = 'Connection Failed.'

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()

