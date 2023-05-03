from SiemplifyUtils import output_handler
from SiemplifyAction import *
import re

def validate_email_address(email_address):
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email_address):
        raise Exception("Email address is not valid")

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Ping"
    configs = siemplify.get_configuration("Siemplify")
    email_address = configs.get("Recipients")

    validate_email_address(email_address)

    output_message = 'Email address is syntactically correct.'
    result_value = 'true'
    siemplify.end(output_message, result_value)

if __name__ == "__main__":
    main()