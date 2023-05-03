# IMPORTS
from EndgameManager import EndgameManager
from TIPCommon import extract_configuration_param, extract_action_param
import arrow
import json

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED

# CONSTS
PROVIDER = u'Endgame'

class EndgameCommon(object):
    def __init__(self, siemplify, logger=None):
        self.logger = logger
        self.siemplify = siemplify

    def get_mapped_environment(self, original_env, map_file):
        """
        Get mapped environment alias from mapping file
        :param original_env: {str} The environment to try to resolve
        :param map_file
        :return: {str} The resolved alias (if no alias - returns the original env)
        """
        try:
            with open(map_file, 'r+') as map_file:
                mappings = json.loads(map_file.read())
        except Exception as e:
            self.logger.error(
                "Unable to read environment mappings: {}".format(str(e)))
            mappings = {}

        if not isinstance(mappings, dict):
            self.logger.LOGGER.error(
                "Mappings are not in valid format. Environment will not be mapped.")
            return original_env

        return mappings.get(original_env, original_env)

    @staticmethod
    def validate_timestamp(last_run_timestamp, offset):
        """
        Validate timestamp in range
        :param last_run_timestamp: {arrow datetime} last run timestamp
        :param offset: {datetime} last run timestamp
        :return: {datetime} if first run, return current time minus offset time, else return timestamp from file
        """
        # Check if first run
        if arrow.get(last_run_timestamp).shift(days=offset) < arrow.utcnow():
            return arrow.utcnow().shift(days=-offset)
        else:
            return last_run_timestamp

    def fetch_investigation_result(self):
        """
        Check investiogation status, if completed retrieve results
        :return:
        """
        self.siemplify.LOGGER.info(u"================= Async - Param Init =================")

        # INIT INTEGRATION CONFIGURATION:
        api_root = extract_configuration_param(self.siemplify, provider_name=PROVIDER, param_name=u"API Root",
                                               is_mandatory=True, input_type=unicode)
        username = extract_configuration_param(self.siemplify, provider_name=PROVIDER, param_name=u"Username",
                                               is_mandatory=True, input_type=unicode)
        password = extract_configuration_param(self.siemplify, provider_name=PROVIDER, param_name=u"Password",
                                               is_mandatory=True, input_type=unicode)
        verify_ssl = extract_configuration_param(self.siemplify, provider_name=PROVIDER, param_name=u"Verify SSL",
                                                 default_value=False, input_type=bool)

        self.siemplify.LOGGER.info(u"----------------- Async - Started -----------------")

        result_value = u"false"
        output_message = u""
        results = []
        status = EXECUTION_STATE_COMPLETED

        action_details = json.loads(self.siemplify.parameters[u"additional_data"])
        investigation_id = action_details[u"investigation_id"]
        successful_entities = action_details[u"successful_entities"]
        missing_entities = action_details[u"missing_entities"]
        failed_entities = action_details[u"failed_entities"]

        try:
            endgame_manager = EndgameManager(api_root, username=username, password=password, use_ssl=verify_ssl)

            # Check if investigation completed
            if endgame_manager.is_investigation_complete(investigation_id):
                self.siemplify.LOGGER.info(u"Investigation {} has completed. Collecting results.".format(investigation_id))

                # Collect the results of the investigation
                investigation_results = endgame_manager.retrieve_investigation_results(
                    investigation_id
                )

                for task_id, investigation_result in investigation_results.items():
                    for result in investigation_result.get(u'Results', []):
                        results.append(result)

                result_value = u"true"
                status = EXECUTION_STATE_COMPLETED
                self.siemplify.result.add_result_json(results)

                if results:
                    output_message = u"Retrieved results from the following investigation in Endgame: {0}\n\n".format(
                        investigation_id
                    )
                else:
                    output_message = u"There are no results for your investigation\n\n"

                output_message += u"Successfully completed hunt on the following entities:\n   {}".format(
                    u"\n   ".join([entity for entity in successful_entities])
                )

                if missing_entities:
                    output_message += u"\n\nThe following entities didn't match an any endpoint and were skipped:\n   {}".format(
                        u"\n   ".join([entity for entity in missing_entities])
                    )

                if failed_entities:
                    output_message += u"\n\nError occurred while initiating hunt on the following entities:\n   {}".format(
                        u"\n   ".join([entity for entity in failed_entities])
                    )

            else:
                self.siemplify.LOGGER.info(u"Investigation {} has not completed yet. Waiting".format(investigation_id))
                output_message = u"Investigation {} has not completed yet. Waiting".format(investigation_id)
                result_value = self.siemplify.parameters[u"additional_data"]
                status = EXECUTION_STATE_INPROGRESS

        except Exception as e:
            self.siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
            self.siemplify.LOGGER.exception(e)
            status = EXECUTION_STATE_FAILED
            result_value = u"false"
            output_message = u"Action didn't complete due to error: {}".format(e)

        finally:
            try:
                endgame_manager.logout()
            except Exception as e:
                self.siemplify.LOGGER.error(u"Logging out failed. Error: {}".format(e))
                self.siemplify.LOGGER.exception(e)

        self.siemplify.LOGGER.info(u"----------------- Async - Finished -----------------")
        self.siemplify.LOGGER.info(u"Status: {}:".format(status))
        self.siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
        self.siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
        return output_message, result_value, status
