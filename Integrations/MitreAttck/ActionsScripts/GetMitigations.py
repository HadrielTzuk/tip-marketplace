from SiemplifyUtils import output_handler
from MitreAttckManager import MitreAttckManager, MITIGATES_RELATIONSHIP
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

INTEGRATION_NAME = u"MitreAttck"
SCRIPT_NAME = u"Mitre Att&ck - Get Mitigations"
ID_IDENTIFIER = u"Attack ID"
EXTERNAL_ID_IDENTIFIER = u"External Attack ID"
NAME_IDENTIFIER = u"Attack Name"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    result_value = False
    status = EXECUTION_STATE_FAILED
    intrusions = []
    attack_id = u''
    attack = None
    source_refs = []
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                           param_name=u"API Root", input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool, print_value=True)

    # INIT ACTION PARAMETERS:
    identifier = extract_action_param(siemplify, param_name=u"Technique ID", print_value=True, is_mandatory=True)
    identifier_type = extract_action_param(siemplify, param_name=u"Identifier Type", print_value=True,
                                           is_mandatory=True, default_value=ID_IDENTIFIER)
    limit = extract_action_param(siemplify, param_name=u"Max Mitigations to Return", print_value=True, input_type=int,
                                 default_value=20)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        manager = MitreAttckManager(api_root, verify_ssl)

        if identifier_type == ID_IDENTIFIER:
            attack_id = identifier
        else:
            if identifier_type == NAME_IDENTIFIER:
                attack = manager.get_attack_pattern_by_name(identifier)
            elif identifier_type == EXTERNAL_ID_IDENTIFIER:
                attack = manager.get_attack_pattern_by_external_id(identifier)
            if attack:
                attack_id = attack.attack_id

        if attack_id:
            for relationship in manager.get_relationships_where_target_ref(attack_id, MITIGATES_RELATIONSHIP):
                if hasattr(relationship, 'source_ref'):
                    source_refs.append(relationship.source_ref)

        if source_refs:
            intrusions = manager.get_all_where_id_in(source_refs, limit)

        if intrusions:
            siemplify.result.add_data_table(
                title=u'Mitigation techniques for {}'.format(identifier),
                data_table=construct_csv([intrusion.to_mitigations_data_table() for intrusion in intrusions])
            )
            siemplify.result.add_result_json([intrusion.to_json() for intrusion in intrusions])
            output_message = u'Found mitigations for {} technique!'.format(identifier)
            for intrusion in intrusions:
                if intrusion.url and intrusion.mitre_external_id:
                    siemplify.result.add_link(u"Link for the external reference: {}".format(intrusion.mitre_external_id),
                                              intrusion.url)
            result_value = True
        else:
            output_message = u'Didn\'t find any mitigations for {} technique!'.format(identifier)

        status = EXECUTION_STATE_COMPLETED
        siemplify.LOGGER.info(u"Finished processing")
    except Exception as e:
        siemplify.LOGGER.error(u'Error fetching Technique')
        siemplify.LOGGER.exception(e)
        output_message = u'Error executing action \"Get Mitigations\". Reason:{}'.format(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
