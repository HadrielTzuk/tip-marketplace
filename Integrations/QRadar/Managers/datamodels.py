import copy
import hashlib
import json
from TIPCommon import dict_to_flat
from UtilsManager import convert_list_to_comma_string


GREEN_COLOR = "#339966"
RED_COLOR = "#ff0000"
ORANGE_COLOR = "#ff9900"

HIGH_CONFIDENCE = "high"
MEDIUM_CONFIDENCE = "medium"
LOW_CONFIDENCE = "low"

RULENAME_LIST_KEY = 'rulename_creEventList'


class BaseModel(object):
    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data

    def to_csv(self):
        return dict_to_flat(self.raw_data)


class Offense(BaseModel):
    def __init__(self, raw_data, rules=None, description=None, event_count=None, assigned_to=None, flow_count=None,
                 inactive=None, protected=None, source_network=None, close_time=None, start_time=None,
                 last_updated_time=None, id=None, categories=None, severity=None, log_sources=None, offense_type=None,
                 relevance=None, domain_id=None, closing_reason_id=None, offense_source=None, status=None,
                 magnitude=None, domain_name=None, **kwargs):
        super().__init__(raw_data)
        self.id = id
        self.rule_ids = rules if rules else []
        self.description = description
        self.event_count = event_count
        self.assigned_to = assigned_to
        self.flow_count = flow_count
        self.inactive = inactive
        self.protected = protected
        self.source_network = source_network
        self.close_time = close_time
        self.start_time = start_time
        self.last_updated_time = last_updated_time
        self.categories = categories if categories else []
        self.severity = severity
        self.log_source_ids = log_sources if log_sources else []
        self.offense_type = offense_type
        self.relevance = relevance
        self.domain_id = domain_id
        self.closing_reason_id = closing_reason_id
        self.offense_source = offense_source
        self.status = status
        self.magnitude = int(magnitude)
        self.domain_name = domain_name

    @property
    def priority(self):
        # Match magnitude to Siemplify priorieis.
        if self.magnitude < 2:
            return -1
        elif self.magnitude < 4:
            return 40
        elif self.magnitude < 6:
            return 60
        elif self.magnitude < 8:
            return 80
        return 100

    def as_extension(self):
        return dict_to_flat(self.as_json())

    def as_json(self):
        temp = copy.deepcopy(self.raw_data)
        temp.update(
            {
                "domain_name": self.domain_name
            }
        )
        return temp


class Rule(BaseModel):
    def __init__(self, raw_data, owner=None, identifier=None, origin=None, creation_date=None, type=None, enabled=None,
                 modification_date=None, name=None, id=None, **kwargs):
        super().__init__(raw_data)
        self.owner = owner
        self.identifier = identifier
        self.origin = origin
        self.creation_date = creation_date
        self.type = type
        self.enabled = enabled
        self.modification_date = modification_date
        self.name = name
        self.id = id


class LogSource(BaseModel):
    def __init__(self, raw_data, id=None, name=None, type_id=None, type_name=None, **kwargs):
        super().__init__(raw_data)
        self.type_id = type_id
        self.type_name = type_name
        self.name = name
        self.id = id


class Event(BaseModel):
    def __init__(self, raw_data, name=None, rule_names=None, qid=None, category=None, description=None, credibility=None,
                 domain_id=None, start_time=None, end_time=None, magnitude=None, relevance=None, severity=None,
                 device_product=None):
        super(Event, self).__init__(raw_data)
        self.name = name
        self.rule_names = rule_names
        self.qid = qid
        self.category = category
        self.description = description
        self.credibility = credibility
        self.domain_id = domain_id
        self.start_time = start_time
        self.end_time = end_time
        self.magnitude = magnitude
        self.relevance = relevance
        self.severity = severity
        self.device_product = device_product
        self.rule_triggered = None

    def as_hash(self):
        return hashlib.md5(json.dumps(self.raw_data, sort_keys=True).encode()).hexdigest()[:16]

    def __hash__(self):
        return int(self.as_hash(), base=16)

    def __eq__(self, other):
        return self.as_hash() == other.as_hash()

    def as_event(self):
        return dict_to_flat(self.modify_event_data())

    def to_json(self):
        return self.modify_event_data()

    def modify_event_data(self):
        event_data = copy.deepcopy(self.raw_data)
        rulename_list = event_data.get(RULENAME_LIST_KEY, [])
        if rulename_list:
            event_data[RULENAME_LIST_KEY] = convert_list_to_comma_string(rulename_list)
        return event_data


class FlawObject(BaseModel):
    def __init__(self, raw_data):
        super(FlawObject, self).__init__(raw_data=raw_data)


class Reason(object):
    def __init__(self, raw_data, reason_id, text):
        self.raw_data = raw_data
        self.id = reason_id
        self.text = text


class ReferenceSet(BaseModel):
    def __init__(self, raw_data, data):
        super(ReferenceSet, self).__init__(raw_data=raw_data)
        self.data = data


class ReferenceMap(BaseModel):
    def __init__(self, raw_data, data):
        super(ReferenceMap, self).__init__(raw_data=raw_data)
        self.data = data

    def to_output_json(self):
        if self.data:
            json_data = []
            for k, v in self.data.items():
                v["key"] = k
                json_data.append(v)
            return json_data


class ReferenceTable(BaseModel):
    def __init__(self, raw_data, data):
        super(ReferenceTable, self).__init__(raw_data=raw_data)
        self.data = data


class MitreMapping(BaseModel):
    def __init__(self, raw_data, rule_name, id, mapping):
        super(MitreMapping, self).__init__(raw_data=raw_data)
        self.rule_name = rule_name
        self.id = id
        self.mapping = mapping

    def to_json(self):
        self.raw_data['rulename'] = self.rule_name
        return self.raw_data

    def to_csv(self):
        return {
            "Rule Name": self.rule_name,
            "Mapping": convert_list_to_comma_string([key for key, value in self.mapping.items()], '; ')
        }

    def to_insight(self):
        content = f'<br><strong>Rule:</strong> {self.rule_name}<br>'
        content += '<body>'

        for key, value in self.mapping.items():
            content += f'<br><strong>Tactic:</strong> {key or "N/A"}'
            confidence = value.get("confidence", "")
            confidence_color = RED_COLOR if confidence == HIGH_CONFIDENCE else GREEN_COLOR \
                if confidence == LOW_CONFIDENCE else ORANGE_COLOR
            content += f'<br><strong>Confidence:</strong><span style="color: {confidence_color};"><strong> ' \
                       f'{confidence.capitalize()}</strong></span><br>'
            for technique_name, technique_data in value.get('techniques', {}).items():
                content += f'<br><strong>Related Technique:</strong> {technique_name or "N/A"}'
                tech_conf = technique_data.get("confidence", "")
                tech_conf_color = RED_COLOR if tech_conf == HIGH_CONFIDENCE else GREEN_COLOR \
                    if confidence == LOW_CONFIDENCE else ORANGE_COLOR
                content += f'<br><strong>Confidence:</strong><span style="color: {tech_conf_color};"><strong> ' \
                           f'{tech_conf.capitalize()}</strong></span><br>'

        content += '</body>'
        content += '<p>&nbsp;</p>'

        return content


class Domain(BaseModel):
    def __init__(self, raw_data, id, name):
        super(Domain, self).__init__(raw_data)
        self.id = id
        self.name = name

class Domain(BaseModel):
    def __init__(self, raw_data, id, name):
        super(Domain, self).__init__(raw_data)
        self.id = id
        self.name = name
