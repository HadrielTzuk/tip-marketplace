from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SymantecATPManager import SymantecATPManager
from SiemplifyDataModel import EntityTypes
from SymantecATPManager import ATPEntityTypes


ATP_PROVIDER = 'SymantecATP'
ACTION_NAME = "SymantecATP_Close Incident"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(ATP_PROVIDER)
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    atp_manager = SymantecATPManager(conf.get('API Root'), conf.get('Client ID'), conf.get('Client Secret'), verify_ssl)
    # Parameters.
    incident_uuid = siemplify.parameters.get('Incident UUID')
    
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    is_closed = False
    
    try:
        is_closed = atp_manager.close_incident(incident_uuid)

    except Exception as err:
        siemplify.LOGGER.error(u"General error performing action {}".format(ACTION_NAME))
        siemplify.LOGGER.exception(err)
        
    if is_closed:
        output_message = u"Incident with uuid {0} was closed.".format(incident_uuid)
    else:
        output_message = u"Incident with uuid {0} was not closed.".format(incident_uuid)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  is_closed: {}\n output_message: {}".format(is_closed, output_message))
   
    siemplify.end(output_message, is_closed)


if __name__ == "__main__":
    main()
