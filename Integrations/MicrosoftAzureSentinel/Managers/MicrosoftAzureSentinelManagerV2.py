from MicrosoftAzureSentinelManager import MicrosoftAzureSentinelManager


CONFIG_PARAMS_MAPPING = {
    'sentinel-check': 'Sentinel-Check',
    'sentinelwork01': 'sentinelWork01'
}


class MicrosoftAzureSentinelManagerV2(MicrosoftAzureSentinelManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.resource = self.map_config(self.resource)
        self.workspace_id = self.map_config(self.workspace_id)
        self.base_url = self._get_base_url()

    @staticmethod
    def map_config(value):
        return CONFIG_PARAMS_MAPPING.get(value, value)
