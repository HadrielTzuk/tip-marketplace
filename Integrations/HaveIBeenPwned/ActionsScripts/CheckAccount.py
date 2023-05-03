from SiemplifyUtils import output_handler
from HaveIBeenPwnedManager import HaveIBeenPwnedManager
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import construct_csv, convert_dict_to_json_result_dict

SCRIPT_NAME = "HaveIBeenPwned - CheckAccount"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration('HaveIBeenPwned')
    api_key = conf.get('Api Key')
    verify_ssl = str(conf.get('Verify SSL', 'False')).lower() == 'true'
    hibp_manager = HaveIBeenPwnedManager(api_key, use_ssl=verify_ssl)

    pwned_entities = []
    json_results = {}

    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.USER:
            if hibp_manager.validate_email(entity.identifier.lower()):
                try:
                    account_breaches_obj = hibp_manager.get_all_breaches_for_an_account(entity.identifier.lower())
                    account_pastes_obj = hibp_manager.get_all_pastes_for_an_account(entity.identifier)

                    if account_breaches_obj or account_pastes_obj:
                        siemplify.add_entity_insight(entity, 'Account have been pwned!', triggered_by='HaveIBeenPwned')
                        pwned_entities.append(entity.identifier.lower())
                        json_results.update({entity.identifier: {}})

                        if account_pastes_obj:
                            json_results[entity.identifier].update({"pastes": [paste.raw_data for paste in
                                                                               account_pastes_obj]})
                            csv_output = construct_csv([paste.as_csv() for paste in account_pastes_obj])
                            siemplify.result.add_data_table('{0} - Pastes'.format(entity.identifier), csv_output)
                        if account_breaches_obj:
                            json_results[entity.identifier].update({"breaches": [breach.raw_data for breach in
                                                                                 account_breaches_obj]})
                            csv_output = construct_csv([breach.as_csv() for breach in account_breaches_obj])
                            siemplify.result.add_data_table('{0} - Breaches'.format(entity.identifier), csv_output)

                except Exception as e:
                    # An error occurred - skip entity and continue
                    siemplify.LOGGER.error("An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                    siemplify.LOGGER.exception(e)

    if pwned_entities:
        output_message = "The following entities were pwned. \n{0}".format(', \n'.join(pwned_entities))
        result_value = ', '.join(pwned_entities)
    else:
        output_message = "Good news! No pwnage found."
        result_value = 'false'

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
