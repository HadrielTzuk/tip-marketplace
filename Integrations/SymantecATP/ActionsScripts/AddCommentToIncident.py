from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SymantecATPManager import SymantecATPManager
from SiemplifyDataModel import EntityTypes
from SymantecATPManager import ATPEntityTypes

ATP_PROVIDER = 'SymantecATP'
ACTION_NAME = "SymantecATP_Add Comment To Incident"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(ATP_PROVIDER)
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    atp_manager = SymantecATPManager(conf.get('API Root'), conf.get('Client ID'), conf.get('Client Secret'), verify_ssl)

    try:
        siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

        # Parameters.
        incident_uuid = siemplify.parameters.get('Incident UUID')
        comment = siemplify.parameters.get('Comment')

        is_added = atp_manager.add_incident_comment(incident_uuid, comment)

        if is_added:
            output_message = "Comment was successfully attached to incident."
        else:
            output_message = "Comment was not attached to the incident."
    
    except Exception as err:
        siemplify.LOGGER.error(u"General error performing action {}".format(ACTION_NAME))
        siemplify.LOGGER.exception(err)
        is_added = False
        output_message = u"General Error performing action {}. Please make sure that the Incident you want to add comment to exists.".format(ACTION_NAME)
        
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  is_added: {}\n output_message: {}".format(is_added, output_message))
  
    siemplify.end(output_message, is_added)

if __name__ == "__main__":
    main()
