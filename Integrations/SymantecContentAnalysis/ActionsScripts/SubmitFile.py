from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SymantecContentAnalysisManager import SymantecContentAnalysisManager

INTEGRATION_PROVIDER = 'SymantecContentAnalysis'
ACTION_NAME = 'SymantecContentAnalysis_Submit File'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(INTEGRATION_PROVIDER)
    verify_ssl = conf.get('Verify SSL').lower() == 'true'
    symantec_manager = SymantecContentAnalysisManager(conf.get('API Root'), conf.get('API Key'), verify_ssl)

    file_reputation_score = 0

    # Parameters
    file_path = siemplify.parameters.get('File Path')

    result = symantec_manager.submit_file(file_path)

    if 'file_reputation' in result:
        file_reputation_score = result.get('file_reputation', {}).get('score', 0)
    elif 'score' in result:
        file_reputation_score = result.get('score', 0)

    if 2 <= file_reputation_score <= 6:
        siemplify.create_case_insight(INTEGRATION_PROVIDER, 'File Found as Suspicious',
                                      '{0} : is suspicious.'.format(file_path), None, None, None)
    if 7 <= file_reputation_score <= 10:
        siemplify.create_case_insight(INTEGRATION_PROVIDER, 'File Found as Malicious',
                                      '{0} : is Malicious.'.format(file_path), None, None, None)

    if file_reputation_score:
        output_message = '"{0}" submitted successfully. \n \n File Reputation Score: {1}'.format(
            file_path,
            file_reputation_score)
    else:
        output_message = '"{0}" file submission timeout.'.format(file_path)

    siemplify.end(output_message, file_reputation_score)


if __name__ == "__main__":
    main()
