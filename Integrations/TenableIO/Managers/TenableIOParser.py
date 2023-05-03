from datamodels import *


class TenableIOParser:
    def build_vulnerabilities_list(self, raw_data):
        return [self.build_vulnerability_object(item) for item in raw_data]

    def build_vulnerability_object(self, raw_data):
        return Vulnerability(
            raw_data=raw_data,
            id=raw_data.get('plugin', {}).get('id'),
            asset_id=raw_data.get('asset', {}).get('uuid'),
            ipv4=raw_data.get('asset', {}).get('ipv4'),
            description=raw_data.get('plugin', {}).get('description'),
            severity=raw_data.get('severity'),
            last_found=raw_data.get('last_found')
        )

    def build_plugin_families_list(self, raw_data):
        return [self.build_plugin_family_object(item) for item in raw_data.get('families', [])]

    def build_plugin_family_object(self, raw_data):
        return PluginFamily(
            raw_data=raw_data,
            id=raw_data.get('id'),
            name=raw_data.get('name'),
            count=raw_data.get('count')
        )

    def build_asset_objects(self, raw_data):
        return [self.build_asset_object(item) for item in raw_data.get('assets', [])]

    @staticmethod
    def build_asset_object(raw_data):
        return Asset(
            raw_data=raw_data,
            id=raw_data.get('id'),
            ipv4=raw_data.get('ipv4', []),
            ipv6=raw_data.get('ipv6', []),
            netbios_name=raw_data.get('netbios_name', []),
            has_agent=raw_data.get("has_agent"),
            last_seen=raw_data.get("last_seen"),
            tags=raw_data.get("tags", []),
            hostname=raw_data.get("hostname", []),
            operating_system=raw_data.get("operating_system", []),
            mac_address=raw_data.get("mac_address", []),
            system_type=raw_data.get("system_type", [])
        )

    def build_vulnerability_details_object(self, raw_data, plugin_id):
        return VulnerabilityDetails(
            raw_data=raw_data,
            synopsis=raw_data.get('info', {}).get('synopsis'),
            solution=raw_data.get('info', {}).get('solution'),
            severity=raw_data.get('info', {}).get('severity'),
            family=raw_data.get('info', {}).get('plugin_details', {}).get('family'),
            plugin_id=plugin_id
        )

    def build_endpoint_vulnerabilities_list(self, raw_data):
        return [self.build_endpoint_vulnerability_object(item) for item in raw_data.get("vulnerabilities", [])]

    def build_endpoint_vulnerability_object(self, raw_data):
        return EndpointVulnerability(
            raw_data=raw_data,
            id=raw_data.get('plugin_id'),
            name=raw_data.get('plugin_name'),
            severity=raw_data.get('severity'),
            family=raw_data.get('plugin_family'),
            count=raw_data.get('count')
        )

    def build_policies_list(self, raw_data):
        return [self.build_policy_object(item) for item in raw_data.get('policies', [])]

    def build_policy_object(self, raw_data):
        return Policy(
            raw_data=raw_data,
            id=raw_data.get('id'),
            name=raw_data.get('name'),
            description=raw_data.get('description'),
            visibility=raw_data.get('visibility'),
            uuid=raw_data.get('template_uuid')
        )

    def build_scanners_list(self, raw_data):
        return [self.build_scanner_object(item) for item in raw_data.get('scanners', [])]

    def build_scanner_object(self, raw_data):
        return Scanner(
            raw_data=raw_data,
            id=raw_data.get('id'),
            name=raw_data.get('name'),
            uuid=raw_data.get('uuid'),
            type=raw_data.get('type'),
            status=raw_data.get('status')
        )

    def build_scan_object(self, raw_data):
        return Scan(
            raw_data=raw_data,
            vulnerabilities=self.build_endpoint_vulnerabilities_list(raw_data)
        )
