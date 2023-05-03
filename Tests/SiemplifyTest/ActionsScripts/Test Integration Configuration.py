from SiemplifyAction import *
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "SIemplifyTest - Test Integration Configuration"
    conf = siemplify.get_configuration("SiemplifyTest")
    boolean = str(conf.get("Boolean", "False")).lower() == "true"
    integer = int(conf.get("Integer", 0)) if conf.get("Integer", 0) else 0
    password = conf.get("Password")
    string = conf.get("String")
    ip = conf.get("IP")
    ip_or_host = conf.get("IP_OR_HOST")
    url = conf.get("URL")
    domain = conf.get("Domain")
    email = conf.get("Email")

    print("Boolean: {}".format(boolean))
    print("Integer: {}".format(integer))
    print("Password: {}".format(password))
    print("String: {}".format(string))
    print("IP: {}".format(ip))
    print("IP_OR_HOST: {}".format(ip_or_host))
    print("Domain: {}".format(domain))
    print("URL: {}".format(url))
    print("Email: {}".format(email))

    output_message = 'Test completed.'
    result_value = 'true'
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
