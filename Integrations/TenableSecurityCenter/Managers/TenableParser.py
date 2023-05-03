from datamodels import *


class TenableParser(object):
    def get_asset_id(self, raw_data, asset_name):
        assets = raw_data.get(u"response", {}).get(u"usable", [])
        return next((asset.get(u"id", u"") for asset in assets if asset.get(u"name", u"") == asset_name), u"")

    def build_scan_object(self, raw_data):
        response = raw_data.get(u"response")

        return Scan(
            raw_data=response
        )

    def build_ip_list_asset(self, raw_data):
        raw_json = raw_data.get(u"response")

        return IPListAsset(
            raw_data=raw_json,
            defined_ips=raw_json.get(u"typeFields", {}).get(u"definedIPs")
        )
