from Integrations.ZohoDesk.Managers.datamodels import (
    Agent,
    Ticket,
    Comment
)
from ZohoDeskParser import ZohoDeskParser

import pytest
import random
import string


@pytest.mark.parametrize(
    "ticket_id, additional_fields",
    [
        (
            115142000000219090, {}
        )
    ]
)
def test_get_ticket(zohodesk_manager, ticket_data, mocker, ticket_id, additional_fields, ):
    res = mocker.spy(ZohoDeskParser, "build_ticket_object")
    try:
        zohodesk_manager.get_ticket(ticket_id, additional_fields)
    except:
        pass

    raw_data = res.call_args.args[0]
    ticket = Ticket(
        raw_data=raw_data,
        id=raw_data.get("id"),
        subject=raw_data.get("subject"),
        description=raw_data.get("description"),
        ticket_number=raw_data.get("ticketNumber"),
        status=raw_data.get("status"),
        created_time=raw_data.get("createdTime"),
        resolution=raw_data.get("resolution"),
        email=raw_data.get("email"),
        first_name=raw_data.get("contact", {}).get("firstName"),
        last_name=raw_data.get("contact", {}).get("lastName")
    )
    assert ticket.ticket_number == ticket_data.ticket_number
    assert ticket.id == ticket_data.id
    assert ticket.subject == ticket_data.subject
    assert ticket.created_time == ticket_data.created_time
    assert ticket.status == ticket_data.status
    assert ticket.description == ticket_data.description


@pytest.mark.parametrize(
    "ticket_id, limit",
    [
        (
            115142000000176001, 10
        )
    ]
)
def test_get_ticket_comments(zohodesk_manager, comment_data, mocker, ticket_id, limit):
    res = mocker.spy(ZohoDeskParser, "build_comment_object")
    try:
        zohodesk_manager.get_ticket_comments(ticket_id, limit)
    except:
        pass

    raw_data = res.call_args.args[0]
    comment = Comment(
        raw_data=raw_data,
        content=raw_data.get("content"),
        commented_time=raw_data.get("commentedTime")
    )
    assert comment.content == comment_data.content
    assert comment.commented_time == comment_data.commented_time


@pytest.mark.parametrize(
    "ticket_id, mark_contact, mark_other_contact_tickets",
    [
        (
            115142000000176001, False, False
        )
    ]
)
def test_mark_ticket_as_spam(zohodesk_manager, ticket_id, mark_contact, mark_other_contact_tickets):
    result = zohodesk_manager.mark_ticket_as_spam(
        ticket_id, mark_contact, mark_other_contact_tickets
    )

    assert result is None


@pytest.mark.parametrize(
    "ticket_id", [115142000000176001]
)
def test_mark_ticket_as_read(zohodesk_manager, ticket_id):
    result = zohodesk_manager.mark_ticket_as_read(ticket_id)

    assert result is True


@pytest.mark.parametrize(
    "ticket_id", [115142000000176001]
)
def test_mark_ticket_as_unread(zohodesk_manager, ticket_id):
    result = zohodesk_manager.mark_ticket_as_unread(ticket_id)

    assert result is True


@pytest.mark.parametrize(
    "ticket_id, is_public, content_type, content",
    [
        (
            115142000000222369, True, "html", "hello"
        )
    ]
)
def test_add_comment(zohodesk_manager, ticket_id, is_public, content_type, content):
    result = zohodesk_manager.add_comment(ticket_id, is_public, content_type, content)

    assert result is None


@pytest.mark.parametrize(
    "agent_name", ["Milen"]
)
def test_find_agent(zohodesk_manager, mocker, agent_data, agent_name):
    result = mocker.spy(ZohoDeskParser, "build_agent_object")
    try:
        zohodesk_manager.find_agent(name=agent_name)
    except:
        pass

    raw_data = result.call_args.args[0]
    agent = Agent(
        raw_data=raw_data,
        id=raw_data.get("id"),
        name=raw_data.get("name"),
        email=raw_data.get("emailId")
    )

    assert agent.id == agent_data.id
    assert agent.name == agent_data.name
    assert agent.email == agent_data.email


@pytest.mark.parametrize(
    "contact_id, department_id, priority, classification",
    [
        (
            "115142000000244013", "115142000000007061",
            "High", "Feature"
        )
    ]
)
def test_create_ticket(
    zohodesk_manager, contact_id, department_id, priority, classification,
    mocker
):
    # setup a spy mock on function args
    result = mocker.spy(ZohoDeskParser, "build_ticket_object")

    # GIVEN
    # create test ticket with a custom title and description
    test_title = f"test_title_{''.join(random.choice(string.ascii_letters) for _ in range(5))}"
    test_description = f"test_description_{''.join(random.choice(string.ascii_letters) for _ in range(5))}"

    try:
        zohodesk_manager.create_ticket(
            title=test_title,
            description=test_description,
            contact_id=contact_id,
            department_id=department_id,
            priority=priority,
            classification=classification,
            assignee_id=None,
            team_id=None,
            channel=None,
            category=None,
            sub_category=None,
            due_date=None,
            custom_fields=None
        )
    except:
        pass

    # WHEN
    raw_data = result.call_args.args[0]

    # THEN
    assert raw_data["id"] is not None
    assert raw_data["subject"] == test_title
    assert raw_data["description"] == test_description
    assert raw_data["contactId"] == contact_id
    assert raw_data["departmentId"] == department_id
    assert raw_data["priority"] == priority
    assert raw_data["classification"] == classification


@pytest.mark.parametrize(
    "contact_id, department_id, priority, classification",
    [
        (
            "115142000000244013", "115142000000007061",
            "High", "Feature"
        )
    ]
)
def test_update_ticket(
    zohodesk_manager, contact_id, department_id, priority, classification,
    mocker
):
    # setup a spy mock on function args
    result = mocker.spy(ZohoDeskParser, "build_ticket_object")

    # GIVEN
    # create test ticket with a custom title and description
    test_title = f"test_title_{''.join(random.choice(string.ascii_letters) for _ in range(5))}"
    test_description = f"test_description_{''.join(random.choice(string.ascii_letters) for _ in range(5))}"

    try:
        zohodesk_manager.create_ticket(
            title=test_title,
            description=test_description,
            contact_id=contact_id,
            department_id=department_id,
            priority=priority,
            classification=classification,
            assignee_id=None,
            team_id=None,
            channel=None,
            category=None,
            sub_category=None,
            due_date=None,
            custom_fields=None
        )
    except:
        pass

    raw_data = result.call_args_list[0].args[0]
    ticket_id = raw_data["id"]

    assert ticket_id is not None

    # WHEN
    # update this ticket with a new title and description
    new_test_title = f"new_test_title_{''.join(random.choice(string.ascii_letters) for _ in range(5))}"
    new_test_description = f"new_test_description_{''.join(random.choice(string.ascii_letters) for _ in range(5))}"

    try:
        zohodesk_manager.update_ticket(
            ticket_id=ticket_id,
            title=new_test_title,
            description=new_test_description
        )
    except:
        pass

    raw_data = result.call_args_list[1].args[0]

    # THEN
    # assert that fields were updated for the same ticket

    assert raw_data["id"] == ticket_id
    assert raw_data["subject"] == new_test_title
    assert raw_data["description"] == new_test_description
