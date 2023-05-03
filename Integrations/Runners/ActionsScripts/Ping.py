from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.end("Success", 'true')


if __name__ == '__main__':
    main()
