from exchangelib import ExtendedProperty, Message


# register VoteRequest Property
class VoteRequest(ExtendedProperty):
    distinguished_property_set_id = "Common"
    property_id = 0x00008520
    property_type = "Binary"


# register VoteResponse Property
class VoteResponse(ExtendedProperty):
    distinguished_property_set_id = "Common"
    property_id = 0x00008524
    property_type = "String"


def register_custom_extended_properties():
    Message.register("vote_request", VoteRequest)
    Message.register("vote_response", VoteResponse)
