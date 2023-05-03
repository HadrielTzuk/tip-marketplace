{
  "size": 100,
  "query": {
        "bool" : {
            "filter" : [
              { "term" : { "level.keyword" : "Error"}},
              { "term" : { "fields.CustomFields.Component.keyword" : "Etl"}},
              { "range" : { "@timestamp": {"gte": <start_unixtime>}}},
              { "range" : { "@timestamp": {"lt": <end_unixtime>}}}
            ]
        }
    }
}