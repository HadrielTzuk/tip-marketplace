from TIPCommon import dict_to_flat, add_prefix_to_dict_keys


ENRICHMENT_PREFIX = u"CB_ENT_EDR"


class Process(object):
    def __init__(self, raw_data, event_id=None, enriched_event_type=None, process_name=None, process_guid=None,
                 process_pid=None, parent_guid=None, parent_pid=None, process_hash=None, process_username=None,
                 device_timestamp=None, event_description=None, event_network_local_ipv4=None,
                 event_network_protocol=None, event_network_remote_ipv4=None, event_network_remote_port=None, **kwargs):
        self.raw_data = raw_data
        self.event_id = event_id
        self.enriched_event_type = enriched_event_type
        self.process_name = process_name
        self.process_guid = process_guid
        self.process_pid = process_pid
        self.parent_guid = parent_guid
        self.parent_pid = parent_pid
        self.process_hash = process_hash
        self.process_username = process_username
        self.device_timestamp = device_timestamp
        self.event_description = event_description
        self.event_network_local_ipv4 = event_network_local_ipv4
        self.event_network_protocol = event_network_protocol
        self.event_network_remote_ipv4 = event_network_remote_ipv4
        self.event_network_remote_port = event_network_remote_port

    def to_csv(self):
        return dict_to_flat({
            u"Event id": self.event_id,
            u"Event Type": self.enriched_event_type,
            u"Process Name": self.process_name,
            u"Process GUID": self.process_guid,
            u"Process PID": u", ".join([unicode(pid) for pid in self.process_pid]) if isinstance(self.process_pid, list) else self.process_pid,
            u"Process Parent GUID": self.parent_guid,
            u"Process Parent PID": self.parent_pid,
            u"Process File Hash": u", ".join([unicode(hash) for hash in self.process_hash]) if isinstance(self.process_hash, list) else self.process_hash,
            u"Process Run As": u", ".join(self.process_username) if isinstance(self.process_username, list) else self.process_username,
            u"Created Time": self.device_timestamp,
            u"Event Description": self.event_description,
            u"Local ipv4 address": self.event_network_local_ipv4,
            u"Network Protocol": self.event_network_protocol,
            u"Remote IPv4 Address": self.event_network_remote_ipv4,
            u"Remote Port": self.event_network_remote_port
        })


class Event(object):
    def __init__(self, raw_data, **kwargs):
        self.raw_data = raw_data

    def to_csv(self):
        return dict_to_flat(self.raw_data)


class FileHashMetadata(object):
    def __init__(self, raw_data, sha256=None, md5=None, architecture=None, available_file_size=None, charset_id=None,
                 comments=None, company_name=None, copyright=None, file_available=None,
                 file_description=None, file_size=None, file_version=None, internal_name=None, lang_id=None,
                 original_filename=None, os_type=None, private_build=None, product_description=None, product_name=None,
                 product_version=None, special_build=None, trademark=None, **kwargs):
        self.raw_data = raw_data
        self.sha256 = sha256
        self.md5 = md5
        self.architecture = architecture
        self.available_file_size = available_file_size
        self.charset_id = charset_id
        self.comments = comments
        self.company_name = company_name
        self.copyright = copyright
        self.file_available = file_available
        self.file_description = file_description
        self.file_size = file_size
        self.file_version = file_version
        self.internal_name = internal_name
        self.lang_id = lang_id
        self.original_filename = original_filename
        self.os_type = os_type
        self.private_build = private_build
        self.product_description = product_description
        self.product_name = product_name
        self.product_version = product_version
        self.special_build = special_build
        self.trademark = trademark

    def as_enrichment_data(self):
        enrichment_data = {
            u"comments": self.comments,
            u"lang_id": self.lang_id,
            u"private_build": self.private_build,
            u"product_description": self.product_description,
            u"special_build": self.special_build,
            u"trademark": self.trademark
        }

        # Clear out None values
        enrichment_data = {k: v for k, v in enrichment_data.items() if v is not None}

        enrichment_data.update({
            u"sha256": self.sha256,
            u"md5": self.md5,
            u"architecture": self.architecture,
            u"available_file_size": self.available_file_size,
            u"charset_id": self.charset_id,
            u"company_name": self.company_name,
            u"copyright": self.copyright,
            u"file_available": self.file_available,
            u"file_description": self.file_description,
            u"file_size": self.file_size,
            u"file_version": self.file_version,
            u"internal_name": self.internal_name,
            u"original_filename": self.original_filename,
            u"os_type": self.os_type,
            u"product_name": self.product_name,
            u"product_version": self.product_version
        })

        return add_prefix_to_dict_keys(dict_to_flat(enrichment_data), ENRICHMENT_PREFIX)


class FileHashSummary(object):
    def __init__(self, raw_data, num_devices=None, first_seen_device_timestamp=None, first_seen_device_id=None,
                 first_seen_device_name=None, last_seen_device_timestamp=None, last_seen_device_id=None,
                 last_seen_device_name=None, **kwargs):
        self.raw_data = raw_data
        self.num_devices = num_devices
        self.first_seen_device_timestamp = first_seen_device_timestamp
        self.first_seen_device_id = first_seen_device_id
        self.first_seen_device_name = first_seen_device_name
        self.last_seen_device_timestamp = last_seen_device_timestamp
        self.last_seen_device_id = last_seen_device_id
        self.last_seen_device_name = last_seen_device_name

    def as_enrichment_data(self):
        enrichment_data = {
            u"found_times": self.num_devices,
            u"first_seen_device_timestamp": self.first_seen_device_timestamp,
            u"first_seen_device_id": self.first_seen_device_id,
            u"first_seen_device_name": self.first_seen_device_name,
            u"last_seen_device_timestamp": self.last_seen_device_timestamp,
            u"last_seen_device_id": self.last_seen_device_id,
            u"last_seen_device_name": self.last_seen_device_name
        }

        return add_prefix_to_dict_keys(dict_to_flat(enrichment_data), ENRICHMENT_PREFIX)