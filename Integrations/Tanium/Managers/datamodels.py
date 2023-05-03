import copy
from constants import ENRICHMENT_PREFIX
from TIPCommon import dict_to_flat, add_prefix_to_dict


class BaseModel(object):
    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data

    def to_flat(self):
        return dict_to_flat(self.to_json())


class Question(BaseModel):
    def __init__(self, raw_data, **kwargs):
        super().__init__(raw_data)
        self.id = raw_data.get("data", {}).get('id', 0)


class QuestionResult(BaseModel):
    def __init__(self, raw_data, short_raw_data, columns, rows):
        super().__init__(raw_data)
        self.short_raw_data = short_raw_data
        self.columns = columns
        self.rows = rows

    def to_json(self):
        raw_data = copy.deepcopy(self.short_raw_data)
        columns = copy.deepcopy(self.columns)
        rows = copy.deepcopy(self.rows)

        for row in rows:
            row['data'] = row['data'][0]

        raw_data.update({
            "columns": columns[:-1],
            "rows": rows
        })

        return raw_data

    def to_csv(self):
        csv = []
        for row in self.rows:
            if row.get('data', []):
                csv.append({
                    self.columns[0].get('name', ''): row.get('data', [])[0][0].get('text')
                })

        return csv

    def to_enrichment_json(self):
        columns = copy.deepcopy(self.columns)[:-1]
        raw_json = {}

        for index, value in enumerate(columns):
            raw_key = value.get('name', '')
            if len(self.rows[0].get('data')[index]) > 1:
                raw_data = ', '.join([item.get('text') for item in self.rows[0].get('data')[index]])
            else:
                raw_data = self.rows[0].get('data')[index][0].get('text')
            raw_json[raw_key] = raw_data

        return raw_json

    def to_enrichment_csv(self):
        return dict_to_flat(self.to_enrichment_json())

    def to_enrichment(self):
        data = self.to_enrichment_json()
        enrichment_data = {}
        for key, val in data.items():
            replaced_key = key.replace(' ', '_')
            enrichment_data[replaced_key] = val

        return add_prefix_to_dict(enrichment_data, ENRICHMENT_PREFIX)


class Connection(BaseModel):
    def __init__(self, raw_data, id, ip, hostname,  client_id, platform, status):
        super().__init__(raw_data)
        self.id = id
        self.ip = ip
        self.hostname = hostname
        self.client_id = client_id
        self.platform = platform
        self.status = status


class Task(BaseModel):
    def __init__(self, raw_data, id, status, file_uuid, file_path, meta_type, meta_id):
        super().__init__(raw_data)
        self.id = id
        self.status = status
        self.file_uuid = file_uuid
        self.file_path = file_path
        self.meta_type = meta_type
        self.meta_id = meta_id
