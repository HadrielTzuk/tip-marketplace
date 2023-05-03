{
  "size": 100,
  "query": {
        "bool" : {
            "filter" : [
              { "term" : { "levelname.keyword" : "ERROR"}},
              { "term" : { "location.keyword" : "SDK_Connectors"}},
              { "range" : { "@timestamp": {"gte": <start_unixtime>}}},
              { "range" : { "@timestamp": {"lt": <end_unixtime>}}}
            ]
        }
    }
}