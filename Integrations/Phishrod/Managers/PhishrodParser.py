from typing import List, Any

from datamodels import Incident


class PhishrodParser:
    def get_results(self, raw_json: dict, builder_method: str) -> List[Any]:
        """
        Default method for building dataclass objects from raw data

        Args:
            raw_json: JSON received from API
            builder_method: Method which will be used to building objects

        Returns:
            List of filled objects
        """
        results = raw_json.get("incidents", [])
        return [getattr(self, builder_method)(result_item) for result_item in results]

    @staticmethod
    def build_incidents(raw_data: dict) -> Incident:
        """
        Builds Incident dataclass

        Args:
            raw_data: Raw API data item

        Returns:
            Filled Incident object
        """
        return Incident(
            raw_data=raw_data,
            email_subject=raw_data.get("emailSubject"),
            incident_number=raw_data.get("incidentNumber"),
            report_datetime=raw_data.get("reportedBy", {})[0].get("reportDateTime"),
        )
