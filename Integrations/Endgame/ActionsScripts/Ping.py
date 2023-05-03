from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from EndgameManager import EndgameManager

PROVIDER = 'Endgame'


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration(PROVIDER)
    api_root = conf['API Root']
    username = conf['Username']
    password = conf['Password']
    use_ssl = str(conf.get('Verify SSL', 'False')).lower() == 'true'
    egm = EndgameManager(api_root, username=username, password=password, use_ssl=use_ssl)

    # logout
    egm.logout()
    siemplify.end("Connection Established.", 'true')


if __name__ == '__main__':
    main()
