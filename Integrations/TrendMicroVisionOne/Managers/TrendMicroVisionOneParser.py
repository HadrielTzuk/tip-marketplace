from typing import List
from datamodels import *
from typing import Any, List, Dict


class TrendMicroVisionOneParser:
    def build_results(self, raw_json: list or dict, method: str, data_key: str = 'items', pure_data: bool = False,
                      limit: int = None, **kwargs) -> [Any]:
        """
        Build results using provided method
        Args:
            raw_json (dict or list): raw data to build results from
            method (str): parser method to use
            data_key (str): key to use to get needed data from raw data
            pure_data (str): specifies if provided raw data should be used as provided or no
            limit (int): limit for results

        Returns:
            ([any]): list of objects
        """
        return [getattr(self, method)(item_json, **kwargs) for item_json in (raw_json if pure_data else
                                                                             raw_json.get(data_key, []))[:limit]]

    @staticmethod
    def get_items(raw_data: dict) -> List or Dict:
        """
        Get items from provided raw data
        Args:
            raw_data (dict): raw data

        Returns:
            (list or dict):
        """
        return raw_data.get("items", {})

    @staticmethod
    def build_alert_object(raw_data: dict) -> Alert:
        """
        Build Alert object from raw data
        Args:
            raw_data (dict): raw data

        Returns:
            (Alert): Alert object
        """
        return Alert(
            raw_data=raw_data,
            alert_id=raw_data.get("id"),
            model=raw_data.get("model"),
            description=raw_data.get("description"),
            severity=raw_data.get("severity"),
            created_datetime=raw_data.get("createdDateTime")
        )

    @staticmethod
    def build_endpoint_obj(raw_json: dict) -> Endpoint:
        """
        Build Endpoint object from raw data
        Args:
            raw_json (dict): raw data

        Returns:
            (Endpoint): Endpoint object
        """
        return Endpoint(
            raw_data=raw_json,
            guid=raw_json.get("agentGuid"),
            os_description=raw_json.get("osDescription"),
            login_account_value=raw_json.get("loginAccount", {}).get("value", []),
            endpoint_name_value=raw_json.get("endpointName", {}).get("value"),
            ip_value=raw_json.get("ip", {}).get("value", []),
            installed_product_codes=raw_json.get("installedProductCodes", [])
        )

    @staticmethod
    def build_task_obj(raw_json: dict) -> Task:
        return Task(
            raw_data=raw_json,
            status=raw_json.get("status"),
            id=raw_json.get("id")
        )

    @staticmethod
    def build_script_objects(raw_json: dict) -> List[Script]:
        return [
            Script(raw_data=script_dict)
            for script_dict in raw_json.get("items", [])
        ]
