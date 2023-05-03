from SiemplifyUtils import output_handler
from SiemplifyAction import *
from FortiManager import FortiManager


PROVIDER = 'FortiManager'
ACTION_NAME = 'FortiManager_Execute Script'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    forti_manager = FortiManager(conf['API Root'], conf['Username'], conf['Password'], verify_ssl)

    # Parameters.
    adom_name = siemplify.parameters.get('ADOM Name')
    policy_package_name = siemplify.parameters.get('Policy Package Name')
    script_name = siemplify.parameters.get('Script Name')
    device_name = siemplify.parameters.get('Device Name')
    vdom = siemplify.parameters.get('VDOM', None)

    task_id = forti_manager.execute_script(adom_name, policy_package_name, script_name, device_name, vdom)

    output_message = "Script executed, The task ID is: {0}".format(task_id)

    siemplify.end(output_message, task_id)


if __name__ == "__main__":
    main()
