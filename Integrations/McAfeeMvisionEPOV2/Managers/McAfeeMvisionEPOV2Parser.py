from datamodels import *


class McAfeeMvisionEPOV2Parser(object):
    def get_auth_token(self, raw_json):
        return '{} {}'.format(raw_json.get('token_type', ''), raw_json.get('access_token', ''))

    def get_total_items(self, raw_json):
        return raw_json.get('meta', {}).get('totalResourceCount')

    def build_siemplify_tag(self, tag_json):
        return Tag(raw_data=tag_json,
                   tag_id=tag_json.get('id'),
                   name=tag_json.get("attributes", {}).get("name"),
                   created_by=tag_json.get("attributes", {}).get("createdBy"),
                   family=tag_json.get("attributes", {}).get("family"),
                   notes=tag_json.get("attributes", {}).get("notes")
                   )

    def build_siemplify_device(self, device_json):
        return Device(
            raw_data=device_json,
            name=device_json.get('attributes', {}).get('name'),
            ip=device_json.get('attributes', {}).get('ipAddress'),
            hostname=device_json.get('attributes', {}).get('ipHostName'),
            device_id=device_json.get('id'),
            agent_guid=device_json.get('attributes', {}).get('agentGuid'),
            last_update=device_json.get('attributes', {}).get('lastUpdate'),
            managed_state=device_json.get('attributes', {}).get('managedState'),
            os_platform=device_json.get('attributes', {}).get('osPlatform'),
            os_type=device_json.get('attributes', {}).get('osType'),
            os_version=device_json.get('attributes', {}).get('osVersion'),
            domain_name=device_json.get('attributes', {}).get('domainName'),
            computer_name=device_json.get('attributes', {}).get('computerName'),
            agent_version=device_json.get('attributes', {}).get('agentVersion'),
            username=device_json.get('attributes', {}).get('userName'),
            tags=[tag.strip() for tag in device_json.get('attributes', {}).get('tags', '').split(',')]
        )

    def build_siemplify_event(self, event_json):
        return Event(
            raw_data=event_json,
            timestamp=event_json.get('attributes', {}).get('timestamp'),
            event_id=event_json.get('id'),
            auto_guid=event_json.get('attributes', {}).get('autoguid'),
            detected_utc=event_json.get('attributes', {}).get('detectedutc'),
            received_utc=event_json.get('attributes', {}).get('receivedutc'),
            agent_guid=event_json.get('attributes', {}).get('agentguid'),
            analyzer_name=event_json.get('attributes', {}).get('analyzername'),
            analyzer_hostname=event_json.get('attributes', {}).get('analyzerhostname'),
            analyzer_ipv4=event_json.get('attributes', {}).get('analyzeripv4'),
            source_ipv4=event_json.get('attributes', {}).get('sourceipv4'),
            source_username=event_json.get('attributes', {}).get('sourceusername'),
            target_ipv4=event_json.get('attributes', {}).get('targetipv4'),
            target_port=event_json.get('attributes', {}).get('targetport'),
            threat_name=event_json.get('attributes', {}).get('threatname'),
            threat_type=event_json.get('attributes', {}).get('threattype'),
            threat_category=event_json.get('attributes', {}).get('threatcategory'),
            threat_severity=event_json.get('attributes', {}).get('threatseverity'),
            threat_event_id=event_json.get('attributes', {}).get('threateventid')
        )
