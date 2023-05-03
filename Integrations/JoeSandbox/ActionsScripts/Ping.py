from SiemplifyUtils import output_handler
from JoeSandboxManager import JoeSandboxManager
from SiemplifyAction import SiemplifyAction


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = 'JoeSandbox - Detonate file'

    conf = siemplify.get_configuration('JoeSandbox')
    api_key = conf['Api Key']
    use_ssl = conf['Use SSL'].lower() == 'true'
    joe = JoeSandboxManager(api_key, use_ssl)

    if joe.test_connectivity():
        output_message = "Connected successfully to JoeSandbox."
        result_value = 'true'
    else:
        output_message = 'Joe Sandbox is in maintenance mode. Please turn it on.'
        result_value = 'false'

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()