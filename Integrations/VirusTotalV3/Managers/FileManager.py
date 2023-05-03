import paramiko

SSH_PORT = 22


class FileManager(object):
    def __init__(self, address, username, password):
        self.address = address
        self.username = username
        self.password = password

    # CR: Document params
    def _get_server_sftp_session(self):
        """
        Create SSH session to remote server
        :return: {object} sftp client object (paramiko data model)
        """
        transport = paramiko.Transport(self.address, SSH_PORT)
        transport.connect(username=self.username, password=self.password)
        return paramiko.SFTPClient.from_transport(transport)

    def get_remote_unix_file_content(self, remote_file_path):
        """
        Retrieve file content (file blob) from remote linux host
        :param remote_file_path: {str} The file path on the remote server
        :return:
        """
        sftp_client = self._get_server_sftp_session()
        file_content = sftp_client.open(remote_file_path, mode='rb')
        # CR: Close the file after reading from it.
        return file_content.read()
