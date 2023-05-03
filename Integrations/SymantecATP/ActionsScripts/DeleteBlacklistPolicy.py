# coding=utf-8
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from TIPCommon import extract_configuration_param, extract_action_param
from SymantecATPManager import SymantecATPManager, SymantecATPBlacklistPolicyNotFoundError, SymantecATPNoBlacklistPoliciesError
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes

# =====================================
#             CONSTANTS               #
# =====================================
SCRIPT_NAME = u'SymantecATP_Delete Blacklist Policy'
INTEGRATION_NAME = u"SymantecATP"
SUPPORTED_ENTITY_TYPES = [EntityTypes.URL, EntityTypes.FILEHASH, EntityTypes.ADDRESS]

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    output_message = u""
    is_success = u"true"
    successfully_deleted_entities=[]
    not_found_entities=[]
    status = EXECUTION_STATE_COMPLETED
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")
    
    # Integration Parameters
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client ID",
                                           is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client Secret",
                                           is_mandatory=True)    
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)
 
    target_entities = [
            entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES
        ]
        
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")    
   
    try:
        atp_manager = SymantecATPManager(api_root, client_id, client_secret, verify_ssl)

        for entity in target_entities:
            try:
                atp_manager.delete_blacklist_policy_by_identifier(entity.identifier, SCRIPT_NAME)  
                successfully_deleted_entities.append(entity)
                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
                        
            except SymantecATPBlacklistPolicyNotFoundError as e:
                not_found_entities.append(entity)
                siemplify.LOGGER.info(u"Blacklist policy for entity {} was not found.".format(entity.identifier))
                        
            except Exception as e: 
                raise e
            
    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message += u"Error executing action Delete BlackList Policy. Reason: {0}".format(e)
        is_success = u"false"   

    if successfully_deleted_entities:
        entities_names = [entity.identifier for entity in successfully_deleted_entities]
        output_message += u'Successfully deleted the following entities from Symantec ATP blacklist policy: \n{}\n'.format(
            '\n'.join(entities_names)
        )        
    else:
        #None of the processed entities were found in ATP
        output_message += u"No policies were deleted."
        is_success = u"false"
        
    if not_found_entities and successfully_deleted_entities:
        entities_names = [entity.identifier for entity in not_found_entities]
        output_message += u'The following entities were not found in the Symantec ATP blacklist policies: \n{}\n'.format(
            '\n'.join(entities_names)
        )
        
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, is_success, output_message))
    siemplify.end(output_message, is_success, status)
    
if __name__ == "__main__":
    main()