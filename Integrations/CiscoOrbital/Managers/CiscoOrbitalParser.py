from datamodels import *


class CiscoOrbitalParser:
    def get_auth_token(self, raw_json):
        return raw_json.get("token")

    def get_job_id(self, raw_json):
        return raw_json.get("ID")

    def get_endpoints_results(self, raw_json, limit):
        return [EndpointResult(
            raw_data=result,
            hostname=result.get("hostinfo", {}).get("hostname"),
            local_ipv4=self.get_local_ips(result, "ipv4"),
            local_ipv6=self.get_local_ips(result, "ipv6"),
            external_ipv4=result.get("hostinfo", {}).get("external", {}).get("ipv4"),
            error=','.join([item.get('error') for item in result.get("osQueryResult", [])
                            if item.get('error', '').strip()]),
            tables_data=self.get_tables_data(result.get("osQueryResult", [])),
            limit=limit
        ) for result in raw_json.get("results", []) or []]

    def get_tables_data(self, results):
        return [TableData(
            columns=result.get("columns", []),
            values=result.get("values", [])
        ) for result in results]

    def get_local_ips(self, result, key):
        return [value.get(key) for name, value in result.get("hostinfo", {}).get("interfaces", {}).items()
                if value.get(key)]
