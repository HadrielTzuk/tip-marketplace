from datamodels import *


class SonicWallParser(object):
    def build_response_object(self, response_json):
        return ResponseObject(
            raw_data=response_json,
            command=response_json.get(u'status', {}).get(u'cli', {}).get(u'command'),
            message=response_json.get(u'status', {}).get(u'info', [])[0].get(u'message'),
            code=response_json.get(u'status', {}).get(u'info', [])[0].get(u'code')
        )

    def build_ip_object(self, response_json):
        return IPObject(
            raw_data=response_json,
            name=response_json.get(u'name'),
            uuid=response_json.get(u'uuid'),
            zone=response_json.get(u'zone'),
            ip=response_json.get(u'host', {}).get(u'ip')
        )

    def build_address_group(self, response_json, ip_type):
        return AddressGroup(
            raw_data=response_json,
            name=response_json.get(u'name'),
            uuid=response_json.get(u'uuid'),
            address_objects=[self.build_ip_object(ip_object) for ip_object in response_json.get(u'address_object', {}
                                                                                                ).get(ip_type, [])]
        )

    def build_uri_list_object(self, response_json):
        return URIListObject(
            raw_data=response_json,
            name=response_json.get(u'name'),
            uri_list=[self.build_uri_object(uri_object) for uri_object in response_json.get(u'uri', [])]
        )

    def build_uri_object(self, response_json):
        return URIObject(
            raw_data=response_json,
            uri=response_json.get(u'uri')
        )

    def build_uri_list_group_object(self, response_json):
        return URIListGroupObject(
            raw_data=response_json,
            name=response_json.get(u'name')
        )

    def build_uri_list(self, response_json):
        return URIListGroupObject(
            raw_data=response_json,
            name=response_json.get(u'name')
        )
        
    def build_uri_group_object(self, response_json):
        return URIGroupObject(
            raw_data=response_json,
            name=response_json.get(u'name'),
            uri_list=[self.build_uri_list_group_object(uri_object) for uri_object in response_json.get(u'uri_list_object', [])],
            uri_group=[self.build_uri_list(uri_object) for uri_object in response_json.get(u'uri_list_group', [])],
        )
        
