from datamodels import *


class SplashParser:
    def build_address_object(self, raw_data):
        return Address(
            raw_data=raw_data,
            original_url=raw_data.get('requestedUrl'),
            final_url=raw_data.get('url'),
            title=raw_data.get('title'),
            history=raw_data.get('history', []),
            har=raw_data.get('har', {}),
            png=raw_data.get('png', "")
        )
