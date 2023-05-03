from datamodels import *


class HCLBigFixInventoryParser:
    def build_results(self, raw_json, method, data_key="rows", pure_data=False, limit=None, **kwargs):
        return [getattr(self, method)(item_json, **kwargs) for item_json in (raw_json if pure_data else
                                                                             raw_json.get(data_key, []))[:limit]]

    def build_device_obj(self, raw_json):
        return Device(raw_json,
                      bigfix_id=raw_json.get("bigfix_id"),
                      name=raw_json.get("name"),
                      dns_name=raw_json.get("dns_name"),
                      ip_address=raw_json.get("ip_address"),
                      os=raw_json.get("os"),
                      first_seen=raw_json.get("first_seen"),
                      last_seen=raw_json.get("last_seen"),
                      is_deleted=raw_json.get("is_deleted"),
                      deletion_date=raw_json.get("deletion_date"),
                      last_scan_attempt=raw_json.get("computer_health", {}).get("last_scan_attempt"),
                      is_out_of_date=raw_json.get("computer_health", {}).get("is_out_of_date"),
                      is_out_of_sync=raw_json.get("computer_health", {}).get("is_out_of_sync"),
                      is_missing_prereqs=raw_json.get("computer_health", {}).get("is_missing_prereqs"),
                      is_low_on_disk_space=raw_json.get("computer_health", {}).get("is_low_on_disk_space")
                      )

