# -*- coding: utf-8 -*-
# ==============================================================================
# title           :EmailIMAPManager.py
# description     :This Module contain all Email cloud operations functionality
# author          :org@siemplify.co
# date            :2-5-18
# python_version  :2.7
# libraries       :email, emaildata
# requirements    :
# product_version :
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================

import ssl
from imaplib import IMAP4, IMAP4_SSL
from urllib.parse import urlparse

import socks
from imapclient import IMAPClient

from EmailCommon import DEFAULT_REGEX_MAP
from EmailDataModelTransformationLayer import EmailDataModelTransformationLayer

OK_STATUS = 'OK'
INBOX_IMAP_FOLDER = "Inbox"


class RFC3501FlagsEnum(object):
    SEEN = '\\SEEN'
    SEEN_BRACKETS = '(\\SEEN)'
    DELETED = '\\DELETED'
    DELETED_BRACKETS = '(\\DELETED)'


class EmailManagerError(Exception):
    """
    General Exception for Email manager
    """
    pass


class ProxyIMAP4(IMAP4):
    def __init__(self,
                 host='',
                 port=143,
                 proxy_type=socks.PROXY_TYPE_SOCKS5,
                 proxy_addr=None,
                 proxy_port=None,
                 proxy_username=None,
                 proxy_password=None):
        self.proxy_type = proxy_type
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        IMAP4.__init__(self, host, port)

    # noinspection PyAttributeOutsideInit
    def open(self, host, port=143):
        self.host = host
        self.port = port
        self.sock = socks.create_connection(dest_pair=(host, port),
                                            proxy_type=self.proxy_type,
                                            proxy_addr=self.proxy_addr,
                                            proxy_port=self.proxy_port,
                                            proxy_username=self.proxy_username,
                                            proxy_password=self.proxy_password)
        self.file = self.sock.makefile('rb')


class ProxyIMAP4SSL(IMAP4_SSL):
    def __init__(self,
                 host='',
                 port=993,
                 keyfile=None,
                 certfile=None,
                 proxy_type=socks.PROXY_TYPE_SOCKS5,
                 proxy_addr=None,
                 proxy_port=None, proxy_username=None,
                 proxy_password=None):
        self.proxy_type = proxy_type
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        IMAP4_SSL.__init__(self, host, port, keyfile, certfile)

    # noinspection PyAttributeOutsideInit
    def open(self, host, port=993):
        self.host = host
        self.port = port
        # actual proxy default setting, but as said, you may want to parameterize it
        self.sock = socks.create_connection(dest_pair=(host, port),
                                            proxy_type=self.proxy_type,
                                            proxy_addr=self.proxy_addr,
                                            proxy_port=self.proxy_port,
                                            proxy_username=self.proxy_username,
                                            proxy_password=self.proxy_password)
        self.sslobj = ssl.wrap_socket(self.sock, self.keyfile, self.certfile)
        self.file = self.sslobj.makefile('rb')


class EmailIMAPManager(object):
    """
    Responsible for all Email system operations functionality
    """

    def __init__(self, mail_address, logger, environment, proxy_server=None, proxy_username=None, proxy_password=None,
                 regex_map=DEFAULT_REGEX_MAP):
        """
        Basic constructor
        :param mail_address: {str} Email address of the mailbox, where email has been found
        :param logger: {SiemplifyLogger} Logger instance
        :param environment: {str} Default environment name
        :param proxy_server: {str} HTTP/HTTPS address of the proxy server
        :param proxy_username: {str} Proxy username
        :param proxy_password: {str} Proxy password as a plaintext
        :param regex_map: {dict} Mapping of email attribute names and regex expressions to extract them from the email body
        """
        self.mail_address = mail_address
        self.logger = logger
        self.translator = EmailDataModelTransformationLayer(logger=self.logger, regex_map=regex_map)
        self.environment = environment

        if proxy_server:
            server_url = urlparse(proxy_server)
            scheme = server_url.scheme

            if scheme and server_url.hostname:
                self.proxy_addr = "{}://{}".format(scheme, server_url.hostname)
                self.proxy_port = server_url.port
            else:
                if ":" in proxy_server:
                    self.proxy_addr = proxy_server.split(":")[0]
                    self.proxy_port = int(proxy_server.split(":")[1])
                else:
                    self.proxy_addr = proxy_server
                    self.proxy_port = None

            self.proxy_username = proxy_username
            self.proxy_password = proxy_password

        else:
            self.proxy_addr = None
            self.proxy_port = None
            self.proxy_username = None
            self.proxy_password = None

        self.imap = None
        self.imap_client = None

    def login_imap(self, host, port, username, password, use_ssl=False):
        if self.proxy_addr:
            self.imap = ProxyIMAP4SSL(
                host=host, port=port,
                proxy_addr=self.proxy_addr,
                proxy_port=self.proxy_port,
                proxy_username=self.proxy_username,
                proxy_password=self.proxy_password
            ) if use_ssl else ProxyIMAP4(
                host=host, port=port,
                proxy_addr=self.proxy_addr,
                proxy_port=self.proxy_port,
                proxy_username=self.proxy_username,
                proxy_password=self.proxy_password
            )
        else:
            self.imap = IMAP4_SSL(host=host, port=int(
                port)) if use_ssl else IMAP4(host=host, port=port)
            self.imap_client = IMAPClient(host, port=int(port), ssl=use_ssl)
        try:
            self.imap.login(username, password)
            self.imap.select()
            # In some cases we are using self.imap_client instead of self.imap in order to use imapclient lib advantages
            self.imap_client.login(username, password)
        except Exception as error:
            raise EmailManagerError("Cannot login to IMAP serve with the given creds, error: {}".format(error))
        return True

    def get_imap_folder_list(self):
        """
        Get all mail account folders. Note - folders returned wrapped with double quotes.
        :return: {string list}
        """
        if not self.imap:
            raise EmailManagerError("Imap Server is no configured yet, call first to self.login_imap()")

        result, mailboxes = self.imap.list()
        if result != OK_STATUS:
            raise EmailManagerError("get_imap_folder_list(): {}".format(mailboxes))

        return [m.decode("utf-8").split(' "/" ')[1] for m in mailboxes]

    def get_message_data_by_message_id(self,
                                       email_uid,
                                       folder_name="Inbox",
                                       mark_as_read=False,
                                       include_raw_eml=False,
                                       additional_headers=None):
        """
        Get email data via IMAP by email_uid
        :param email_uid: {str} Unique email ID
        :param folder_name: {str} Name of the mailbox to search emails in (e.g. 'Inbox' or 'Threads')
        :param mark_as_read: {bool} mark mails as read after fetching them, Default is False
        :param include_raw_eml: {bool} get the mail eml (in eml format)
        :param additional_headers: {list} The list of the headers/header_regexp to add to the final result
        :return: {dict} Email Object represented by a dict
        """
        if folder_name:
            self.select_folder(folder_name)

        # Migrated to (BODY.PEEK[]) from (RFC822) in order to download attachments
        result, data = self.imap.uid('fetch', email_uid, '(BODY.PEEK[])')
        if result != OK_STATUS:
            raise EmailManagerError("receive_mail(): ERROR getting message {0}".format(email_uid))

        if mark_as_read:
            self.mark_email_as_read(email_uid, mark_as_read=True)

        if not data:
            return None

        return self.translator.convert_string_to_email(
            email_string=data[0][1],
            email_uid=email_uid,
            environment=self.environment,
            mailbox=self.mail_address,
            include_raw_email=include_raw_eml,
            additional_headers=additional_headers)

    def receive_mail_ids(self,
                         folder_name='Inbox',
                         subject_filter=None,
                         content_filter=None,
                         time_filter=None,
                         only_unread=False,
                         message_id=None,
                         reply_to=None,
                         sender=None,
                         recipient=None):
        """
        Get mails from account folder using filters.
        All these filters are applied together using logical AND condition.
        Note: It can't filter with unicode string!
        :param folder_name: {str} Name of the mailbox to search emails in (e.g. 'Inbox' or 'Threads')
        :param subject_filter: {str} Email subject to filter by
        :param content_filter: {str} Specific content to look for in email body
        :param time_filter: {datetime} Timestamp, containing tzinfo. Method would return emails, which have been received after this timestamp
        :param only_unread: {bool} Fetch only unread mails
        :param message_id: {str} Look for email with specific message_id
        :param reply_to: {str} Method would look for all emails, which have been responses to an email with this message_id
        :param sender: {str} Method would filter emails by provided sender email.
        :param recipient: {str} Method would filter emails, which have been send to this recipient.
        :return: {list} Messages uids
        """
        if not self.imap:
            raise EmailManagerError("Imap Server is no configured yet, call first to self.login_imap()")

        self.select_folder(folder_name)

        filters = []
        imap_client_filter = []
        if only_unread:
            filters.append("NOT SEEN")
            imap_client_filter.append("NOT")
            imap_client_filter.append("SEEN")
        if subject_filter:
            filters.append("SUBJECT \"{}\"".format(subject_filter))
            imap_client_filter.append("SUBJECT")
            imap_client_filter.append(subject_filter.encode())
        if content_filter:
            filters.append("BODY \"{}\"".format(content_filter))
            imap_client_filter.append("BODY")
            imap_client_filter.append(content_filter.encode())
        if time_filter:
            filters.append("SINCE \"{}\"".format(time_filter.strftime("%d-%b-%Y")))
            imap_client_filter.append("SINCE")
            imap_client_filter.append(time_filter.strftime("%d-%b-%Y").encode())
        if message_id:
            filters.append("HEADER Message-ID \"{}\"".format(message_id))
            imap_client_filter.append("HEADER")
            imap_client_filter.append("Message-ID")
            imap_client_filter.append(message_id)
        if sender:
            filters.append("HEADER FROM \"{}\"".format(sender))
            imap_client_filter.append("FROM")
            imap_client_filter.append(sender.encode())
        if recipient:
            filters.append("HEADER TO \"{}\"".format(recipient))
            imap_client_filter.append("TO")
            imap_client_filter.append(recipient.encode())
        if reply_to:
            in_reply_filter = f"HEADER In-Reply-To \"{reply_to}\""
            x_microsoft_filter = f"HEADER X-Microsoft-Original-Message-ID \"{reply_to}\""
            amazon_references_filter = f"HEADER References \"{reply_to}\""

            # "OR" takes only two arguments, so we need to chain them together
            # every new header should increase leading "ORs" by one
            filters.append(
                f"(OR OR {' '.join([in_reply_filter, x_microsoft_filter, amazon_references_filter])})"
            )

            imap_client_filter.append("HEADER")
            imap_client_filter.append("In-Reply-To")
            imap_client_filter.append(reply_to)

            imap_client_filter.append("HEADER")
            imap_client_filter.append("X-Microsoft-Original-Message-ID")
            imap_client_filter.append(reply_to)

            imap_client_filter.append("HEADER")
            imap_client_filter.append("References")
            imap_client_filter.append(reply_to)

        if filters:
            where = "({0})".format(" ".join(filters))
        else:
            where = "ALL"
            imap_client_filter = ["ALL"]

        try:
            result, all_data = self.imap.uid('search', None, where)
        except Exception as e:
            # since imap does not have easy support for unicode text, in case of fail we will try same query with imapclient
            try:
                self.imap_client.select_folder(folder_name)
                result, all_data = OK_STATUS, self.imap_client.search(imap_client_filter, 'utf-8')
                if all_data:
                    return [str(data) for data in all_data]
            except:
                raise e

        if result != OK_STATUS:
            raise EmailManagerError(
                "Error in receive_mail() finding messages. {0}: Status={1} Data={2}".format(
                    where, result, all_data))

        if not all_data:
            return []
        # @TODO check this
        return [str(id, 'utf-8') for id in all_data[0].split()]

    def mark_email_as_read(self, email_uid, mark_as_read=True):
        """
        Mark specific email as read/unread
        :param email_uid: {String}
        :param mark_as_read: {Boolean}
        """
        if mark_as_read:
            try:
                self.imap.uid('store', email_uid, '+FLAGS', RFC3501FlagsEnum.SEEN)
            except:
                # Some providers need the flag to be in brackets (i.e: Fastmail)
                self.imap.uid('store', email_uid, '+FLAGS', RFC3501FlagsEnum.SEEN_BRACKETS)
        else:
            try:
                self.imap.uid('store', email_uid, '-FLAGS', RFC3501FlagsEnum.SEEN)
            except:
                # Some providers need the flag to be in brackets (i.e: Fastmail)
                self.imap.uid('store', email_uid, '-FLAGS', RFC3501FlagsEnum.SEEN_BRACKETS)

    def move_mail(self, email_uid, source_folder, target_folder):
        """
        Moves email from current folder to the target one by email_uid
        :param email_uid: {str} Email UID, which represents an email to be moved
        :param source_folder: {str} Mailbox, from which email should be moved
        :param target_folder: {str} Mailbox, where email should be moved
        :return:
        """
        self.select_folder(source_folder)

        result, data = self.imap.uid('move', email_uid, target_folder)
        if result != OK_STATUS:
            raise EmailManagerError("move_mail() failed: {}".format(result))

        return data

    def delete_mail(self, email_uid, folder_name="Inbox"):
        """
        Deletes a specific email
        :param email_uid: {str} Email UID, which represents an email to be deleted
        :param folder_name: {str} Name of the mailbox to search emails in (e.g. 'Inbox' or 'Threads')
        """
        self.select_folder(folder_name)

        try:
            self.imap.uid('store', email_uid, '+FLAGS', RFC3501FlagsEnum.DELETED)
        except:
            # Some providers need the flag to be in brackets (i.e: Fastmail)
            self.imap.uid('store', email_uid, '+FLAGS', RFC3501FlagsEnum.DELETED_BRACKETS)
        self.imap.expunge()

    def select_folder(self, folder_name):
        result, data = self.imap.select(folder_name)

        if result != OK_STATUS:
            raise EmailManagerError("Folder {} not found ".format(folder_name))
