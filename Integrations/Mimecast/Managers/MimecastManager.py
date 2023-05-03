from urllib.parse import urljoin
import requests
import base64
import hashlib
import hmac
import uuid
import datetime
from constants import *
from UtilsManager import validate_response, lazy_chunk_iterable
from TIPCommon import filter_old_alerts
from MimecastParser import MimecastParser


class MimecastManager:
    def __init__(self, api_root, app_id, app_key, access_key, secret_key, verify_ssl=False, siemplify=None):
        """
        The method is used to init an object of Manager class
        :param api_root: {str} API root of the Mimecast instance.
        :param app_id: {str} Application ID of the Mimecast instance.
        :param app_key: {str} Application Key of the Mimecast instance.
        :param access_key: {str} Access Key of the Mimecast instance.
        :param secret_key: {str} Secret Key of the Mimecast instance.
        :param verify_ssl: {bool} If enabled, verify the SSL certificate for the connection to the server is valid.
        :param siemplify: Siemplify Connector Executor
        """
        self.api_root = api_root[:-1] if api_root.endswith("/") else api_root
        self.app_id = app_id
        self.app_key = app_key
        self.access_key = access_key
        self.secret_key = secret_key
        self.siemplify = siemplify
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.parser = MimecastParser()
        self.session.headers = HEADERS

    def _generate_request_headers(self, uri):
        """
        Request access token
        :param uri: {str} Request endpoint.
        :return: {dict} Request headers
        """
        # Generate request header values
        request_id = str(uuid.uuid4())
        hdr_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"

        # DataToSign is used in hmac_sha1
        data_to_sign = ':'.join([hdr_date, request_id, uri, self.app_key])

        # Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
        hmac_sha1 = hmac.new(base64.b64decode(self.secret_key), data_to_sign.encode(), digestmod=hashlib.sha1).digest()

        # Use the HMAC SHA1 value to sign the hdrDate + ":" requestId + ":" + URI + ":" + appkey
        sig = base64.b64encode(hmac_sha1).rstrip()

        # Create request headers
        headers = {
            'Authorization': 'MC ' + self.access_key + ':' + sig.decode(),
            'x-mc-app-id': self.app_id,
            'x-mc-date': hdr_date,
            'x-mc-req-id': request_id,
            'Content-Type': 'application/json'
        }

        return headers

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param root_url: {str} The API root for the request
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.api_root, ENDPOINTS[url_id].format(**kwargs))

    def test_connectivity(self):
        """
        Test connectivity
        """
        request_url = self._get_full_url("ping")
        self.session.headers.update(self._generate_request_headers(uri=ENDPOINTS["ping"]))
        response = self.session.post(request_url)
        validate_response(response)

    def search_emails(self, existing_ids, limit, start_timestamp, domains, statuses, routes):
        """
        Search for emails
        :param existing_ids: {list} The list of existing ids
        :param limit: {int} The limit for results
        :param start_timestamp: {datetime} The timestamp for oldest message to fetch
        :param domains: {list} List of domains for which to query messages
        :param statuses: {list} Statuses to filter the messages
        :param routes: {list} Routes to filter the messages
        :return: {list} The list of filtered Message objects
        """
        url = self._get_full_url("email_search")
        payload = {
            "data": [
                {
                    "start": start_timestamp.strftime(FILTER_TIME_FORMAT),
                    "status": statuses,
                    "route": routes
                }
            ]
        }
        messages = []
        for domain in domains:
            payload["data"][0]["advancedTrackAndTraceOptions"] = {
                "to": domain
            }
            response = self.session.post(url, json=payload,
                                         headers=self._generate_request_headers(uri=ENDPOINTS["email_search"]))
            validate_response(response)
            messages.extend(self.parser.build_messages_list(response.json()))

        sorted_emails = sorted(messages, key=lambda message: message.received)
        filtered_emails = set()
        for sorted_emails_chunk in lazy_chunk_iterable(sorted_emails, limit):
            for email_base in sorted_emails_chunk:
                email_base.message_details = self.get_message_details(email_base.tracking_id)
            filtered_emails.update(filter_old_alerts(
                siemplify=self.siemplify,
                alerts=sorted_emails_chunk,
                existing_ids=existing_ids,
                id_key=ALERT_ID_KEY
            ))
            if len(filtered_emails) >= limit:
                break

        return list(filtered_emails)[:limit]

    def get_message_details(self, message_id):
        """
        Get message details with id
        :param message_id: {str} The id of the message
        :return: {MessageDetails}
        """
        url = self._get_full_url("get_email_details")
        payload = {
            "data": [
                {
                    "id": message_id
                }
            ]
        }

        response = self.session.post(url, json=payload,
                                     headers=self._generate_request_headers(uri=ENDPOINTS["get_email_details"]))
        validate_response(response)

        return self.parser.build_message_details_object(response.json())

    def manage_sender(self, sender, recipient, action):
        """
        Function that manages senders, either block them or permits them
        :param sender: Sender who should be either permitted or blocked
        :param recipient: Recipient who should be either permitted or blocked
        :param action: Action - Permit/Block
        """

        request_url = self._get_full_url('manage_sender')
        self.session.headers.update(self._generate_request_headers(uri=ENDPOINTS["manage_sender"]))
        payload = {
            "data": [
                {
                    "action":action,
                    "to": recipient,
                    "sender": sender
                }
            ]
        }

        result = self.session.post(request_url, json=payload)
        validate_response(result)

    def reject_message(self, message_id, note, reason, notify_sender):
        """
        Function that rejects the message in Mimecast
        :param message_id: Message ID
        :param note: Rejection Note
        :param reason: Reason for rejection
        :param notify_sender: Value that indicates if the sender should be notified
        """
        request_url = self._get_full_url('reject_message')
        self.session.headers.update(self._generate_request_headers(uri=ENDPOINTS["reject_message"]))

        reason = REJECTION_REASONS.get(reason)

        data_payload = {
                    "id":message_id,
                    "notify":notify_sender
                }
        if note is not None:
            data_payload["notes"] = note


        if reason != SELECT_ONE_REASON:
            data_payload["reason"] = reason

        payload = {
            "data": [
                data_payload
            ]
        }

        result = self.session.post(request_url, json=payload)
        validate_response(result)

    def report_message(self, message_id, comment, report_as):
        """
        Function that reports the message in Mimecast
        :param message_id: Message ID
        :param comment: Comment to add to the report
        :param report_as: Type of the report Spam/Malware/Phising
        """
        request_url = self._get_full_url('report_message')
        self.session.headers.update(self._generate_request_headers(uri=ENDPOINTS["report_message"]))
        report_type = REPORT_TYPES.get(report_as)


        data_payload = {
                    "id":message_id,
                    "type": report_type
                }

        if comment is not None:
            data_payload["comment"] = comment

        payload = {
            "data": [
                data_payload
            ]
        }

        result = self.session.post(request_url, json=payload)
        validate_response(result)

    def release_message(self, message_id):
        """
        Function that releases the message in Mimecast
        :param message_id: Message ID
        """
        request_url = self._get_full_url('release_message')
        self.session.headers.update(self._generate_request_headers(uri=ENDPOINTS["release_message"]))

        payload = {
            "data": [
                {
                    "id":message_id
                }
            ]
        }

        result = self.session.post(request_url, json=payload)
        validate_response(result)

    def release_message_to_sandbox(self, message_id):
        """
        Function that releases the message to Sandbox in Mimecast
        :param message_id: Message ID
        """
        request_url = self._get_full_url('release_message_sandbox')
        self.session.headers.update(self._generate_request_headers(uri=ENDPOINTS["release_message_sandbox"]))

        payload = {
            "data": [
                {
                    "id":message_id
                }
            ]
        }

        result = self.session.post(request_url, json=payload)
        validate_response(result)

    def execute_query(self, xml_query):
        """
        Function that exexutes the query in XML in Mimecast
        :param xml_query: XML Query
        :return: {BaseModel} Base Model object containing query results
        """
        request_url = self._get_full_url('execute_query')
        self.session.headers.update(self._generate_request_headers(uri=ENDPOINTS["execute_query"]))

        payload = {
            "meta": {
            },
            "data": [
                {
                    "admin": True,
                    "query": xml_query
                }
            ]
        }

        result = self.session.post(request_url, json=payload)
        validate_response(result)
        return self.parser.build_base_model(result.json())

    def execute_query_with_pagination(self, xml_query, limit):
        """
        Archive search with pagination
        :param xml_query: {str} Search query
        :param limit: {int} Number of emails to return
        :return: {BaseModel} Base Model object containing query results
        """
        request_url = self._get_full_url('execute_query')
        self.session.headers.update(self._generate_request_headers(uri=ENDPOINTS["execute_query"]))

        payload = {
            "meta": {
            },
            "data": [
                {
                    "admin": True,
                    "query": xml_query
                }
            ]
        }

        search_results = self.parser.build_list_of_base_objects(self._paginate_results(method='POST', url=request_url,
                                                                                       body=payload))
        return search_results[:limit]

    def _paginate_results(self, method, url, params=None, body=None, err_msg="Unable to get results"):
        """
        Paginate the results of a request
        :param method: {str} The method of the request (GET, POST, PUT, DELETE, PATCH)
        :param url: {str} The url to send request to
        :param params: {dict} The params of the request
        :param body: {dict} The json payload of the request
        :param err_msg: {str} The message to display on error
        :return: {list} List of results
        """
        if params is None:
            params = {}

        if body is None:
            body = {}

        response = self.session.request(method, url, params=params, json=body)

        validate_response(response, err_msg)
        data = response.json().get("data")
        results = data[0].get("items", []) if data else []
        next_page_token = response.json().get("meta", {}).get("pagination", {}).get("next")

        while next_page_token:
            body.update({
                "meta": {
                    "pagination": {
                        "pageToken": next_page_token
                    }
                }
            })

            response = self.session.request(method, url, params=params, json=body)
            validate_response(response, err_msg)
            data = response.json().get("data")
            next_page_token = response.json().get("meta", {}).get("pagination", {}).get("next")
            results.extend(data[0].get("items", []) if data else [])

        return results

    def build_query(self, fields, mailboxes, from_addresses, to_addresses, subject, start_time, end_time):
        """
        Prepare the search query
        :param fields: {list} List of fields to return
        :param mailboxes: {list} List of mailboxes
        :param from_addresses: {list} List of email addresses from which the emails were sent
        :param to_addresses: {list} List of email addresses to which the emails were sent
        :param subject: {str} Subject that needs to be searched
        :param start_time: {str} Start time for search
        :param end_time: {str} End time for search
        """

        query = "<?xml version=\"1.0\"?><xmlquery trace=\"iql,muse\"><metadata query-type=\"emailarchive\" " \
                "archive=\"true\" active=\"false\" page-size=\"100\" startrow=\"0\">"
        if mailboxes:
            query += "<mailboxes>"
            query += f" ".join([f"<mailbox include-aliases='true'>{mailbox}</mailbox>" for mailbox in mailboxes])
            query += "</mailboxes>"

        query += f"<smartfolders/><return-fields>"
        query += f" ".join([f"<return-field>{field}</return-field>" for field in fields])
        query += f"</return-fields></metadata><muse>"

        if from_addresses:
            query += "<text>"
            query += f" or ".join([f"from:{address}" for address in from_addresses])
            query += "</text>"

        if to_addresses:
            query += "<text>"
            query += f" or ".join([f"to:{address}" for address in to_addresses])
            query += "</text>"

        if subject:
            query += f"<text>subject:{subject}</text>"

        query += f"<date select=\"between\" from=\"{start_time}\" to=\"{end_time}\"/>"
        query += "<docs select=\"optional\"></docs><route/></muse></xmlquery>"

        return query
