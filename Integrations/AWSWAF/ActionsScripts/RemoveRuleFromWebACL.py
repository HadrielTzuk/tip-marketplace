from collections import defaultdict

from TIPCommon import extract_configuration_param, extract_action_param

import consts
from AWSWAFManager import AWSWAFManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, DEFAULT_DDL_SCOPE, DEFAULT_RULE_SOURCE_TYPE, DEFAULT_IP_SET_ACTION, DEFAULT_PRIORITY
from exceptions import AWSWAFValidationException, AWSWAFNotFoundException, AWSWAFWebACLNotFoundException
from utils import load_csv_to_set, is_action_approaching_timeout, get_param_scopes

SCRIPT_NAME = "Remove Rule From Web ACL"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info("================= Main - Param Init =================")


    # INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="AWS Secret Key",
                                                 is_mandatory=True)

    aws_default_region = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                     param_name="AWS Default Region",
                                                     is_mandatory=True)

    web_acl_names = extract_action_param(siemplify, param_name="Web ACL Names",
                                         is_mandatory=True,
                                         print_value=True)

    scope = extract_action_param(siemplify,
                                 param_name="Scope",
                                 is_mandatory=True,
                                 print_value=True,
                                 default_value=DEFAULT_DDL_SCOPE)

    rule_name = extract_action_param(siemplify, param_name="Rule Name",
                                                is_mandatory=True,
                                                print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    waf_web_acls = []  # list of Web ACL data models representing Web ACLs in AWS WAF
    new_web_acls = defaultdict(list)
    successful_web_acls = defaultdict(list)
    failed_web_acls = defaultdict(list)
    not_found_rules = defaultdict(list)
    missing = defaultdict(list)
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    output_message = ''

    try:
        web_acl_names = load_csv_to_set(csv=web_acl_names, param_name="Web ACL Names")
        scopes = get_param_scopes(scope)

        siemplify.LOGGER.info('Connecting to AWS WAF Service')
        waf_client = AWSWAFManager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                   aws_default_region=aws_default_region)
        waf_client.test_connectivity()  # this validates the credentials
        siemplify.LOGGER.info("Successfully connected to AWS WAF service")

        new_existing_web_acls = defaultdict(list)
        for sc in scopes:  # get all existing Web ACLs in specified scopes in AWS WAF
            sc_web_acls = waf_client.list_web_acls(scope=sc)
            waf_web_acls += sc_web_acls
            new_web_acls[sc] += sc_web_acls
            new_existing_web_acls[sc] += [web_acl for web_acl in new_web_acls[sc] if
                             web_acl.name in web_acl_names]
            missing[sc] += web_acl_names.difference(set([web_acl.name for web_acl in new_existing_web_acls[sc]]))

        existing_web_acls = [web_acl for web_acl in waf_web_acls if
                             web_acl.name in web_acl_names]  # existing Web ACLs in  AWS WAF

        acls = []
        for sc in scopes:
            acls += new_existing_web_acls[sc]

        if not acls:  # at least one web acl name must exist in AWS WAF
            raise AWSWAFWebACLNotFoundException(
                "Failed to find Web ACL names {} in the {} AWS WAF service. ".format('\n  '.join(web_acl_names),
                                                                                     consts.BOTH_SCOPE if len(
                                                                                         scopes) == 2 else scope))
        for web_acl in existing_web_acls:
            if is_action_approaching_timeout(siemplify):
                status = EXECUTION_STATE_TIMEDOUT
                break

            try:
                siemplify.LOGGER.info(f"Retrieving existing Web ACL rules from {web_acl.scope} Web ACL {web_acl.name}")
                lock_token, web_acl = waf_client.get_web_acl(scope=web_acl.scope, name=web_acl.name,
                                                             id=web_acl.web_acl_id)
                siemplify.LOGGER.info(f"Successfully retrieved list of rules from {web_acl.name}")

                # rules in a web acl in WAF
                waf_rule_list = web_acl.rules or []

                # rules without the rule to remove
                waf_rule_list_after_remove = [rule for rule in waf_rule_list if rule.name != rule_name]

                # if the lists different in size, the rule with the 'rule_name' found and should be removed
                if len(waf_rule_list_after_remove) != len(waf_rule_list):
                    siemplify.LOGGER.info(f"Removing rule {rule_name} to Web ACL {web_acl.name}")
                    waf_client.remove_web_acl(
                        name=web_acl.name,
                        scope=web_acl.scope,
                        rules=[rule.as_dict() for rule in waf_rule_list_after_remove],
                        id=web_acl.web_acl_id,
                        sampled_requests_enabled=web_acl.sampled_requests_enabled,
                        cloudwatch_metrics_enabled=web_acl.cloudwatch_metrics_enabled,
                        cloudwatch_metric_name=web_acl.cloudwatch_metric_name,
                        lock_token=lock_token,
                        default_action=web_acl.default_action
                    )

                    siemplify.LOGGER.info(
                        f"Successfully removed rule {rule_name} from {web_acl.scope} Web ACL {web_acl.name}")
                    successful_web_acls[web_acl.scope].append(web_acl.name)

                else:
                    not_found_rules[web_acl.scope].append(web_acl.name)

            except Exception as error:  # failed to update Web ACL in AWS WAF
                failed_web_acls[web_acl.scope].append(web_acl.name)
                siemplify.LOGGER.error(error)
                siemplify.LOGGER.exception(error)

        for sc in scopes:
            if successful_web_acls.get(sc):
                web_acls = successful_web_acls.get(sc)
                web_acls_str = '\n'.join(web_acls)
                output_message += f"\nSuccessfully removed a rule from the following " \
                                  f"{consts.UNMAPPED_SCOPE.get(sc)} Web ACLs: {web_acls_str}\n"
                result_value = True

            if not_found_rules.get(sc):
                web_acls = not_found_rules.get(sc)
                web_acls_str = '\n'.join(web_acls)
                output_message += f"Action wasn’t able to find the specified rule in the following" \
                                  f" {consts.UNMAPPED_SCOPE.get(sc)} Web ACLs in AWS WAF:\n{web_acls_str}\n"

            if failed_web_acls.get(sc):
                web_acls = failed_web_acls.get(sc)
                web_acls_str = '\n'.join(web_acls)
                output_message += f"Action wasn't able to find the following {consts.UNMAPPED_SCOPE.get(sc)}" \
                                  f" Web ACLs in AWS WAF:\n{web_acls_str}\n"

            if missing.get(sc):
                missing_web_acl_names_str = "\n".join(missing.get(sc))
                output_message += f"\nAction wasn't able to find the following " \
                                  f"{consts.UNMAPPED_SCOPE.get(sc)} Web ACLs in AWS WAF: \n" \
                                  f"{missing_web_acl_names_str}"

    except AWSWAFWebACLNotFoundException as error:
        output_message = "Action didn't find the provided Web ACLs."
        siemplify.LOGGER.error(error)
        siemplify.LOGGER.exception(error)

    except Exception as error:  # action failure that stops a playbook
        siemplify.LOGGER.error(f"Error executing action '{SCRIPT_NAME}'. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action '{SCRIPT_NAME}'. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()