# ==============================================================================
# title           :ThreatQManager.py
# description     :This Module contain all ThreatQ API functionality
# author          :victor@siemplify.co
# date            :28-12-17
# python_version  :2.7
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
import requests
from urlparse import urljoin
from ThreatQParser import ThreatQParser
from constants import (
    INDICATOR_TYPE_MAPPING,
    OBJECT_TYPE_MAPPING,
    STATUS_MAPPING,
    SCORE_MAPPING,
    ASCENDING_SORT
)
from datamodels import Indicator, Adversary
from custom_exceptions import (
    ThreatQManagerException,
    ObjectNotFoundException,
    ListRelatedObjectsException,
    RelatedObjectNotFoundException,
    SourceObjectNotFoundException,
    DestinationObjectNotFoundException,
    LinkObjectsException,
    MalwareDetailsException,
    MalwareDetailsNotFoundException,
    ObjectCreateException,
    EventCreateException,
    IndicatorScoreException
)

from datamodels import (
    Indicator,
    Adversary,
    LinkedObject,
    MalwareDetails
)

# =====================================
#            Json payloads            #
# =====================================
GET_TOKEN_PAYLOAD = {"email": "", "password": ""}

# =====================================
#               CONSTS                #
# =====================================
API_HOST_FORMAT = u"https://{0}/api/"
AUTH_PARAM_NAME = u"Authorization"
AUTH_PARAM_FORMAT = u"{0} {1}"

RESULTS_PER_PAGE = 25

API_ENDPOINTS = {
    "token": u"token",
    "indicators": u"indicators",
    "indicators_details": u"indicators/{0}/details",
    "indicators_query": u"indicators/query",
    "objects": u"{0}",
    "link_objects": u"{0}/{1}/{2}",
    "adversaries": u"adversaries",
    "add_attribute": u"{0}/{1}/attributes",
    "add_source": u"{0}/{1}/sources",
    "malware": u"malware",
    "entity_related_objects": u"indicators/{0}/{1}",
    "update_indicator_status": u"indicators/{0}",
    "create_event": u"events",
    "link_entities": u"{0}/{1}/{2}",
    "update_indicator_score": u"indicator/{0}/scores",
    "list_events": u'events'
}

GENERAL_PAYLOAD = {
    "criteria": {},
    "filters": {
        "+or": [
            {
                "+and": [
                    {
                        "+and": [
                            {
                                "+or": [
                                    {
                                        "value": {
                                            "is": u""
                                        }
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "+and": [
                            {
                                "+or": []
                            }
                        ]
                    }
                ]
            }
        ]
    }
}

# =====================================
#              FILTERS                #
# =====================================

HASH_FILTER = [
    {
        "type_name": u"MD5"
    },
    {
        "type_name": u"Fuzzy Hash"
    },
    {
        "type_name": u"GOST Hash"
    },
    {
        "type_name": u"Hash ION"
    },
    {
        "type_name": u"SHA-1"
    },
    {
        "type_name": u"SHA-256"
    },
    {
        "type_name": u"SHA-384"
    },
    {
        "type_name": u"SHA-512"
    }
]

IP_FILTER = [
    {
        "type_name": "IP Address"
    },
    {
        "type_name": "IPv6 Address"
    }
]

URL_FILTER = [
    {
        "type_name": "URL"
    }
]

CVE_FILTER = [
    {
        "type_name": "CVE"
    }
]

EMAIL_FILTER = [
    {
        "type_name": "Email Address"
    }
]


# =====================================
#              CLASSES                #
# =====================================


class ApiToken(object):
    """
    API token object which contains token properties.
    """

    def __init__(self, access_token, token_type, expires_in, refresh_token):
        """
        :param access_token: {string}
        :param token_type: {string}
        :param expires_in: {string}
        :param refresh_token: {string}
        """
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = expires_in
        self.refresh_token = refresh_token


class ThreatQManager(object):
    """
    ThreatQ integration logic implementations.
    """

    def __init__(self, server_address, client_id, username, password, verify_ssl=False):
        """
        :param server_address: {string}
        :param client_id: {string}
        :param username: {string}
        :param password: {string}
        """
        self.server_address = server_address
        self.client_id = client_id
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.api_root = API_HOST_FORMAT.format(self.server_address)
        self.api_token = self.get_connection_token()
        self.headers = {
            AUTH_PARAM_NAME: AUTH_PARAM_FORMAT.format(self.api_token.token_type.title(), self.api_token.access_token)}
        self.parser = ThreatQParser()

    def get_connection_token(self):
        """
        Get ThreatQ connection token.
        :return: ApiToken object: The ApiToken object
        """
        # Request
        GET_TOKEN_PAYLOAD['email'] = self.username
        GET_TOKEN_PAYLOAD['password'] = self.password
        request_url = urljoin(self.api_root, API_ENDPOINTS["token"])
        params = {
            "grant_type": u"password",
            "client_id": self.client_id
        }
        response = self.session.post(request_url, params=params, json=GET_TOKEN_PAYLOAD)
        self.validate_response(response, u"Error getting token")

        # Map response content to variables
        api_token_json = response.json()
        access_token = api_token_json.get("access_token")
        token_type = api_token_json.get("token_type")
        expires_in = api_token_json.get("expires_in")
        refresh_token = api_token_json.get("refresh_token")

        # Return ApiToken object.
        return ApiToken(access_token, token_type, expires_in, refresh_token)

    def get_indicator_details(self, indicator):
        """
        Get The Indicator details from ThreatQ
        :param indicator: The indicator valye
        :return: IndicatorDetails object or Throws exception
        """

        indicator_id = self.get_indicator_id(indicator)

        indicator_details_url = urljoin(self.api_root, API_ENDPOINTS["indicators_details"].format(
            indicator_id))
        result = self._get_result(method="GET", url=indicator_details_url,
                                  error_msg=u"Couldn't get indicator details")

        return self.parser.build_indicator_details_object(result)

    def get_indicator_id(self, indicator):
        """
        Returns the Indicator ID
        :param indicator: The indicator
        :return: returns the Indicator ID or throws exception
        """
        get_id_request_url = urljoin(self.api_root, API_ENDPOINTS["indicators"])
        params = {
            "value": indicator
        }
        # Request to ThreatQ.
        response = self.session.get(get_id_request_url, params=params, headers=self.headers, verify=False)
        self.validate_response(response)

        response_json = response.json()

        if response_json.get("data"):
            indicator_id = response_json.get("data")[0].get("id")
            if indicator_id is not None:
                return indicator_id

        raise ThreatQManagerException(u"Error: Couldn't get indicator ID, {}".format(response_json))

    def get_malware_id(self, malware):
        """
        Returns the Malware ID
        :param malware: The malware
        :return: returns the Malware ID or throws exception
        """
        get_id_request_url = urljoin(self.api_root, API_ENDPOINTS["malware"])
        params = {
            "value": malware
        }
        # Request to ThreatQ.
        response = self.session.get(get_id_request_url, params=params, headers=self.headers, verify=False)
        self.validate_response(response)

        response_json = response.json()

        if response_json.get("data"):
            malware_id = response_json.get("data")[0].get("id")
            if malware_id is not None:
                return malware_id

        raise ThreatQManagerException(u"Error: Couldn't get malware ID, {}".format(response_json))

    def get_adversary_id(self, adversary):
        """
        Returns the Adversary ID
        :param adversary: The adversary
        :return: returns the Adversaries ID or throws exception
        """
        get_id_request_url = urljoin(self.api_root, API_ENDPOINTS["adversaries"])
        params = {
            "name": adversary
        }
        # Request to ThreatQ.
        response = self.session.get(get_id_request_url, params=params, headers=self.headers, verify=False)
        self.validate_response(response)

        response_json = response.json()

        if response_json.get("data"):
            adversary_id = response_json.get("data")[0].get("id")
            if adversary_id is not None:
                return adversary_id

        raise ThreatQManagerException(u"Error: Couldn't get malware ID, {}".format(response_json))

    def get_hash_object(self, hash_value):
        """
        Getting the hash object
        :return:
        """
        url = urljoin(self.api_root, API_ENDPOINTS["indicators_query"])
        params = {"sort": u"-updated_at"}
        hash_payload = self.update_payload(hash_value, HASH_FILTER)

        result = self._get_result(method="POST", url=url, body=hash_payload, params=params,
                                  error_msg=u"Couldn't get information for hash")

        return self.parser.build_indicator_object(result)

    def get_ip_object(self, ip_value):
        """
        Getting the IP object from the ThreatQ
        :param ip_value: The IP address
        :return:
        """
        url = urljoin(self.api_root, API_ENDPOINTS["indicators_query"])
        params = {"sort": u"-updated_at"}
        ip_payload = self.update_payload(ip_value, IP_FILTER)

        result = self._get_result(method="POST", url=url, body=ip_payload, params=params,
                                  error_msg=u"Couldn't get information for IP")

        return self.parser.build_indicator_object(result)

    def get_url_object(self, url_value):
        """
        Getting the URL object from the ThreatQ
        :param ip_value: The IP address
        :return:
        """
        url = urljoin(self.api_root, API_ENDPOINTS["indicators_query"])
        params = {"sort": u"-updated_at"}
        url_payload = self.update_payload(url_value, URL_FILTER)

        result = self._get_result(method="POST", url=url, body=url_payload, params=params,
                                  error_msg=u"Couldn't get information for URL")

        return self.parser.build_indicator_object(result)

    def get_cve_object(self, cve_value):
        """
        Getting the enriched CVE object from the ThreatQ
        :param cve_value: CVE value
        :return: CVE object
        """
        url = urljoin(self.api_root, API_ENDPOINTS["indicators_query"])
        params = {"sort": u"-updated_at"}
        cve_payload = self.update_payload(cve_value, CVE_FILTER)

        result = self._get_result(method="POST", url=url, body=cve_payload, params=params,
                                  error_msg=u"Couldn't get information for CVE")

        return self.parser.build_indicator_object(result)

    def get_email_object(self, email_value):
        """
        Getting the enriched Email object from the ThreatQ
        :param email_value: The Email value
        :return: Email object
        """

        url = urljoin(self.api_root, API_ENDPOINTS["indicators_query"])
        params = {"sort": u"-updated_at"}
        email_payload = self.update_payload(email_value, EMAIL_FILTER)

        result = self._get_result(method="POST", url=url, body=email_payload, params=params,
                                  error_msg=u"Couldn't get information for Email")

        return self.parser.build_indicator_object(result)

    def get_object_id(self, object_type, identifier, indicator_type=None, object_exception=ObjectNotFoundException):
        # type: (str or unicode, str or unicode or int, str or unicode, type(ObjectNotFoundException)) -> int or ObjectNotFoundException
        """
        Get Object ID
        @param object_type: Type of the object
        @param identifier: Identifier of the object
        @param indicator_type: Indicator type to convert it to indicator ID
        @param object_exception: Object exception to raise with
        @return: Object ID
        """
        url = urljoin(self.api_root, API_ENDPOINTS["objects"].format(object_type))
        params = self._get_params(
            object_type=object_type,
            identifier=identifier,
            indicator_type=indicator_type
        )

        response = self.session.get(url, params=params, headers=self.headers)
        self.validate_response(response)

        objs = self.parser.build_linked_object_object(response.json())
        if not objs:
            raise object_exception('Object not found')

        # Take the first element in list
        return objs[0].id

    def get_related_objects(
            self,
            source_object_type,
            source_identifier,
            source_indicator_type,
            related_object_type,
            limit=None
    ):
        # type: (str or unicode, str or unicode or int, str or unicode, str or unicode, int) -> [LinkedObject]
        """
        Get related objects
        @param source_object_type: Type of the source object
        @param source_identifier: Identifier of the source object
        @param source_indicator_type: Indicator type of the source object
        @param related_object_type: Type of the related object type
        @param limit: Limit list of the related objects
        """
        source_object_type = OBJECT_TYPE_MAPPING.get(source_object_type)
        related_object_type = OBJECT_TYPE_MAPPING.get(related_object_type)

        source_object_id = self.get_object_id(
            object_type=source_object_type,
            identifier=source_identifier,
            indicator_type=source_indicator_type,
            object_exception=SourceObjectNotFoundException,
        )

        url = urljoin(
            self.api_root,
            API_ENDPOINTS["link_objects"].format(source_object_type, source_object_id, related_object_type)
        )

        response = self.session.get(url, headers=self.headers)
        self.validate_response(response, custom_exception=ListRelatedObjectsException)

        related_objects = self.parser.build_linked_object_object(
            response.json(),
            related_object_type=related_object_type
        )

        if not related_objects:
            raise RelatedObjectNotFoundException('No related objects found')

        return related_objects[:limit]

    def get_entity_related_objects(self, related_object_type, indicator, limit=None):
        """
        Get entity related objects.
        :param related_object_type: Type of the related object
        :param indicator: The indicator value
        :param limit: Limit list of the related objects
        :return: List of Objects
        """
        related_object_type = OBJECT_TYPE_MAPPING.get(related_object_type)
        indicator_id = self.get_indicator_id(indicator=indicator)

        url = urljoin(self.api_root, API_ENDPOINTS["entity_related_objects"].format(indicator_id, related_object_type))

        response = self.session.get(url, headers=self.headers, params={"limit": limit})
        self.validate_response(response)

        related_objects = self.parser.build_entity_related_objects(
            response.json(),
            related_object_type=related_object_type
        )

        return related_objects
    
    def update_indicator_status(self, indicator, status):
        """
        Update Indicator Status.
        :param indicator: The indicator value
        :param status: Status of the indicator
        :return: Indicator object or Error
        """
        indicator_id = self.get_indicator_id(indicator=indicator)

        url = urljoin(self.api_root, API_ENDPOINTS["update_indicator_status"].format(indicator_id))

        response = self.session.put(url, headers=self.headers, params={"status_id": STATUS_MAPPING.get(status)})
        self.validate_response(response)

        update_indicator = self.parser.build_updated_indicator_object(response.json())
        return update_indicator


    def update_indicator_score(self, indicator, score, score_validation):
        """
        Update Indicator Status.
        :param indicator: The indicator value
        :param score: New score to be used for update of the indicator
        :param score_validation: Score Validation to be used for update of the indicator
        :return: Indicator object or Error
        """
        indicator_id = self.get_indicator_id(indicator=indicator)

        #get current indicator score
        indicators_details = self.get_indicator_details(indicator=indicator)
        
        indicator_manual_score = indicators_details.raw_data.get("score",{}).get("manual_score")
        indicator_generated_score = indicators_details.raw_data.get("score",{}).get("generated_score")
        
        if score_validation == u"Highest Score" and SCORE_MAPPING.get(score) < indicator_manual_score and SCORE_MAPPING.get(score) < indicator_generated_score:
            raise IndicatorScoreException(u"Current score is higher.")
        
        url = urljoin(self.api_root, API_ENDPOINTS["update_indicator_score"].format(indicator_id))
        
        response = self.session.put(url, headers=self.headers, params={"manual_score": SCORE_MAPPING.get(score)})
        self.validate_response(response)

        indicator_score = self.parser.build_indicator_score_object(response.json())
        return indicator_score
       
    def add_attribute_to_object(self, object_type, object_identifier, indicator_type, attribute_name, attribute_value, attribute_source):
        """
        Add attribute to an object
        @param object_type: Type of the object
        @param object_identifier: Identifier of the object
        @param indicator_type: Indicator type of the object
        @param attribute_name: Name of the attribute
        @param attribute_value: Value of the attribute
        @param attribute_source: Source of the attribute
        @return: Object
        """
        object_type = OBJECT_TYPE_MAPPING.get(object_type)

        object_id = self.get_object_id(
            object_type=object_type,
            identifier=object_identifier,
            indicator_type=indicator_type)

        url = urljoin(self.api_root, API_ENDPOINTS["add_attribute"].format(object_type, object_id))

        payload = {
            "name": attribute_name,
            "value": attribute_value
        }
        if attribute_source:
            payload["sources"] = [
                {
                    "name": attribute_source
                }
            ]

        response = self.session.post(url, json=payload, headers=self.headers)
        self.validate_response(response, custom_exception=ObjectCreateException)

        return self.parser.build_universal_object(response.json())

    def add_source_to_object(self, object_type, object_identifier, indicator_type, source_name):
        """
        Add source to an object
        @param object_type: Type of the object
        @param object_identifier: Identifier of the object
        @param indicator_type: Indicator type of the object
        @param source_name: Name of the source
        @return: Object
        """
        object_type = OBJECT_TYPE_MAPPING.get(object_type)

        object_id = self.get_object_id(
            object_type=object_type,
            identifier=object_identifier,
            indicator_type=indicator_type)

        url = urljoin(self.api_root, API_ENDPOINTS["add_source"].format(object_type, object_id))
        payload = {
            "name": source_name
        }

        response = self.session.post(url, json=payload, headers=self.headers)
        self.validate_response(response, custom_exception=ObjectCreateException)

        return self.parser.build_universal_object(response.json())

    def link_objects(
            self,
            source_object_type,
            source_identifier,
            destination_object_type,
            destination_identifier,
            source_indicator_type=None,
            destination_indicator_type=None,
    ):
        # type: (str or unicode, str or unicode or int, str or unicode, str or unicode, str or unicode or int, str or unicode) -> Object or ObjectNotFoundException
        source_object_type = OBJECT_TYPE_MAPPING.get(source_object_type)
        destination_object_type = OBJECT_TYPE_MAPPING.get(destination_object_type)

        source_object_id = self.get_object_id(
            object_type=source_object_type,
            identifier=source_identifier,
            indicator_type=source_indicator_type,
            object_exception=SourceObjectNotFoundException
        )

        destination_object_id = self.get_object_id(
            object_type=destination_object_type,
            identifier=destination_identifier,
            indicator_type=destination_indicator_type,
            object_exception=DestinationObjectNotFoundException
        )

        url = urljoin(
            self.api_root,
            API_ENDPOINTS["link_objects"].format(source_object_type, source_object_id, destination_object_type)
        )

        payload = [
            {
                'id': destination_object_id
            }
        ]

        response = self.session.post(url, json=payload, headers=self.headers)
        self.validate_response(response, custom_exception=LinkObjectsException)

        linked_objects = self.parser.build_linked_object_object(response.json())
        if not linked_objects:
            raise ObjectNotFoundException('Object not found')

        return linked_objects[0]


    def link_entities(self, object_type1, object_type2, object_id1, object_id2):
        """
        Link Entities in ThreatQ
        @param object_type1: Opbject Type 1 in structure: object_type1/object_id1/object_type2/object_type2 which is used as an endpoint for linking
        @param object_type2: Opbject Type 1 in structure: object_type1/object_id1/object_type2/object_type2 which is used as an endpoint for linking
        @param object_id1: Opbject Type 1 in structure: object_type1/object_id1/object_type2/object_type2 which is used as an endpoint for linking
        @param object_id2: Opbject Type 1 in structure: object_type1/object_id1/object_type2/object_type2 which is used as an endpoint for linking
        @return Indicator object or Exception
        """  
        url = urljoin(self.api_root, API_ENDPOINTS['link_entities'].format(object_type1, object_id1, object_type2))
        
        payload = {
            'id': object_id2
        }
        
        response = self.session.post(url, json=payload, headers=self.headers)
        self.validate_response(response, custom_exception=LinkObjectsException)
        
        return self.parser.build_link_object(response.json())

    def create_indicator(self, value, indicator_type, status, description=None):
        # type: (unicode or str, unicode or str, unicode or str, unicode or str) -> Indicator or ThreatQManagerException
        """
        Create indicator in ThreatQ
        @param value: Indicator value
        @param indicator_type: Indicator type string that will be converted to a proper int
        @param status: Indicator status string that will be converted to a proper int
        @param description: Description (optional) that will be in indicator
        @return Indicator object or Exception
        """        
        if indicator_type == u"File Hash":
            #Map different hash types to values
            if len(value) == 32:
                #MD5
                indicator_type = u"MD5"
            elif len(value) == 40:
                #SHA-1
                indicator_type = u"SHA-1"
            elif len(value) == 64:
                #SHA-256
                indicator_type = u"SHA-256"                
            elif len(value) == 96:
                #SHA-384
                indicator_type = u"SHA-384"                
            elif len(value) == 128:
                #SHA-512
                indicator_type = u"SHA-512"
            else:
                raise ThreatQManagerException(u"Processed entity is not type hash, indicator type: \"File Hash\" supports only hash entities.")
              
        url = urljoin(self.api_root, API_ENDPOINTS['indicators'])
        payload = {
            'value': value,
            'type_id': INDICATOR_TYPE_MAPPING.get(indicator_type),
            'status_id': STATUS_MAPPING.get(status),
            'description': description
        }

        result = self._get_result(
            method='POST',
            url=url,
            body=payload,
            error_msg='Failed to create indicator'
        )

        return self.parser.build_indicator_object(result)
    
    def create_event(self, title, event_type, happened_at=None):
        """
        Create events in ThreatQ
        @param title: Event title
        @param event_type: Event type string that will be converted to a proper int
        @param happened_at: Time specifying when the event occured
        @return Indicator object or Exception
        """
        url = urljoin(self.api_root, API_ENDPOINTS['create_event'])
        payload = {
            'title': title,
            'type': event_type,
            'happened_at': happened_at
        }

        response = self.session.post(url, headers=self.headers, json=payload)
        self.validate_response(response, error_msg="Failed to create object", custom_exception=EventCreateException)

        return self.parser.build_event_object(response.json())    
    
    def get_malware_details(self, value, additional_information):
        # type: (str or unicode, str or unicode) -> MalwareDetails or MalwareDetailsException or MalwareDetailsNotFoundException
        """
        Get malware details
        @param value:
        @param additional_information:
        @return:
        """
        url = urljoin(self.api_root, API_ENDPOINTS['malware'])
        params = {
            'value': value,
            'with': additional_information,
        }

        response = self.session.get(url, params=params, headers=self.headers)
        self.validate_response(response, custom_exception=MalwareDetailsException)

        malwares_details = self.parser.build_malware_details_object(response.json())
        if not malwares_details:
            raise MalwareDetailsNotFoundException('Malware details not found')

        return malwares_details[0]

    def create_adversary(self, name):
        # type: (unicode or str) -> Adversary or ThreatQManagerException
        """
        Create adversary in ThreatQ
        @param name: Adversary name
        @return Adversary
        """
        url = urljoin(self.api_root, API_ENDPOINTS['adversaries'])
        payload = {
            'name': name
        }

        response = self.session.post(url, headers=self.headers, json=payload)
        self.validate_response(response, 'Failed to create adversary')

        return self.parser.build_adversary_object(response.json().get('data', {}))

    def create_object(self, object_type, value, description):
        """
        Create object in ThreatQ
        :param object_type: Type of the object
        :param value: Object value
        :param description: Object description
        :return: Object
        """
        object_type = OBJECT_TYPE_MAPPING.get(object_type)
        url = urljoin(self.api_root, API_ENDPOINTS["objects"].format(object_type))
        payload = {
            "value": value,
            "description": description
        }

        response = self.session.post(url, headers=self.headers, json=payload)
        self.validate_response(response, error_msg="Failed to create object", custom_exception=ObjectCreateException)

        return self.parser.build_default_object(response.json())

    def list_events(self, sort_field, sort_direction, additional_fields, limit):
        """
        List events from ThreatQ
        :param sort_field: Value to use for sorting
        :param sort_direction: Direction to sort (Ascending or Descending)
        :param additional_fields: Additional fields to be included in the response
        :param limit: How many events to return
        :return: {list} List of Events
        """
        url = urljoin(self.api_root, API_ENDPOINTS['list_events'])
        sort_direction = u'' if sort_direction == ASCENDING_SORT else u'-'
        sort_param = sort_direction + sort_field
        
        if additional_fields:
            additional_fields = additional_fields.replace(" ", "")
        
        params = {
            u'limit': limit,
            u'with': additional_fields,
            u'sort': sort_param
        }
        response = self.session.get(url, headers=self.headers, params=params)
        self.validate_response(response, error_msg="Failed to list events")

        results = response.json().get(u'data', [])
        return [self.parser.build_event_object(event_json) for event_json in results]

    def get_object_name(self, object_id, object_type):
        """
        Get name from the object ID in ThreatQ
        :param object_id: The object ID
        :param object_type: The object type
        :return: None or name
        """
        
        if object_type == u"indicators":
            object_name_url = urljoin(self.api_root, API_ENDPOINTS["indicators"])
            params = {
                "id": object_id
            }
            
        elif object_type == u"adversaries":
            object_name_url = urljoin(self.api_root, API_ENDPOINTS["adversaries"])

        elif object_type == u"malware":
            object_name_url = urljoin(self.api_root, API_ENDPOINTS["malware"])
    
        else:
            raise ThreatQManagerException(u"Error: Unknown object type: {}".format(object_type))
            

        params = {
                "id": object_id
            }    
        
        # Request to ThreatQ.
        response = self.session.get(object_name_url, params=params, headers=self.headers, verify=False)
        self.validate_response(response)

        response_json = response.json()

        if response_json.get("data"):
            if object_type in ["indicators", "malware"]:
                object_id = response_json.get("data")[0].get("value")
                if object_id is not None:
                    return object_id
            
            if object_type in ["adversaries"]:
                object_id = response_json.get("data")[0].get("name")
                if object_id is not None:
                    return object_id

        raise ThreatQManagerException(u"Error: Couldn't get name for the object with ID: ".format(object_id))

    @staticmethod
    def get_value_param(object_type, link_obj):
        if object_type in ['events', 'attachments']:
            return link_obj.title
        elif object_type in ['adversaries', 'signatures', 'tasks']:
            return link_obj.name
        else:
            return link_obj.value

    @staticmethod
    def _get_params(object_type, identifier, indicator_type=None):
        if object_type in ['events', 'attachments']:
            return {'title': identifier}
        elif object_type in ['adversaries', 'signatures', 'tasks']:
            return {'name': identifier}
        elif object_type == 'indicators':
            return {'value': identifier, 'type_id': INDICATOR_TYPE_MAPPING.get(indicator_type)}
        else:
            return {'value': identifier}

    def _get_result(self, method, url, headers=None, body=None, params=None, error_msg=None):
        """
        The method gets all the results using pagination
        :param method: The request method
        :param url: The Url
        :param headers: Headers, in this case the function uses self.headers
        :param body: The request body
        :param params: The params
        :param error_msg: The error message to show in case of error
        :return: The list of a results
        """
        if params is None:
            params = {}
        params.update({"limit": RESULTS_PER_PAGE,
                       "offset": 0})

        response = self.session.request(method, url, params=params, headers=self.headers, json=body)
        self.validate_response(response, error_msg=error_msg)
        total = response.json().get("total", 0)
        results = response.json().get("data", [])
        while total > len(results):
            params["offset"] += 1
            response = self.session.request(method, url, params=params, headers=self.headers, json=body)
            self.validate_response(response, error_msg=error_msg)
            results.extend(response.json().get("data", []))

        return results

    @staticmethod
    def update_payload(value_to_set, filters):
        """
        Update the GENERAL PAYLOAD with the given value and filter
        :param value_to_set: The value
        :param filters: The list of filters
        :return: Updated payload
        """
        updated_payload = GENERAL_PAYLOAD.copy()
        updated_payload["filters"]["+or"][0]["+and"][0]["+and"][0]["+or"][0]["value"]["is"] = value_to_set
        updated_payload["filters"]["+or"][0]["+and"][1]["+and"][0]["+or"] = filters
        return updated_payload

    @staticmethod
    def validate_response(response, error_msg=u"An error occurred", custom_exception=ThreatQManagerException):
        """
        Validated the response from requests Lib
        At first raises for the status, Then
        Checks if the content is JSON

        :param response: The response object
        :param error_msg: The error message for exception
        :param custom_exception: Custom exception to raise with
        :return: True if success or Throws exception
        """
        try:
            response.raise_for_status()
            # trying to cast to JSON, because all the requests are in JSON format
            response.json()
        except requests.HTTPError as error:
            try:
                response.json()
            except:
                # Not a JSON - return content
                raise custom_exception(
                    u"{error_msg}: {error} - {text}".format(
                        error_msg=error_msg,
                        error=error,
                        text=response.content)
                )

            raise custom_exception(
                u"{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=response.json().get('name'),
                    text=response.json().get('message', response.content))
            )
        except Exception as error:
            # Not a JSON - Raise an exception
            raise custom_exception(
                u"{error_msg}: {error} - {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=response.content)
            )

        return True
