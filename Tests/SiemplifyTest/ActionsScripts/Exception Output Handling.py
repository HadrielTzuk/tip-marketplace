from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

@output_handler
def main():
    siemplify = SiemplifyAction()
    print "Sample output"
    if siemplify.parameters.get("Fail", "False").lower() == 'true':
        raise Exception("ERROR")
    output_message = 'Test completed.'
    result_value = 'true'
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()