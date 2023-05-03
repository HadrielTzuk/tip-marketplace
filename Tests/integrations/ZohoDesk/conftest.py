from SiemplifyMarketPlace.Integrations.ZohoDesk.Managers.ZohoDeskManager import ZohoDeskManager

import json
import pytest

from collections import namedtuple


@pytest.fixture(scope="module")
def zohodesk_manager():
    with open("config.json", "r") as f:
        data = f.read()

    config = json.loads(data)

    api_root = config.get("api_root")
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")
    refresh_token = config.get("refresh_token")
    verify_ssl = config.get("verify_ssl")

    yield ZohoDeskManager(api_root, client_id, client_secret, refresh_token, verify_ssl)


@pytest.fixture(scope="function")
def ticket_data():
    Ticket = namedtuple("Ticket", "created_time description id status subject ticket_number")

    ticket = Ticket(
        created_time="2022-08-12T10:12:02.000Z",
        description="fff",
        id="115142000000219090",
        status="Open",
        subject="abc def ghi jkl mno pqrs tuv wxyz ABC DEF GHI JKL MNO PQRS TUV WXYZ !\"§ $%& /() =?* '<> #|; ²³~ @`´ ©«» ¤¼× {} abc def ghi jkl mno pqrs tuv wxyz ABC DEF GHI JKL MNO PQRS TUV WXYZ !\"§ $%& /() =?* '<> #|; ²³~ @`´ ©«» ¤¼× {} abc def ghi jkl mno pqrs tuv wxyz",
        ticket_number="126"
    )
    yield ticket


@pytest.fixture(scope="function")
def comment_data():
    Comment = namedtuple("Comment", "content commented_time")

    comment = Comment(
        content="<div style=\"font-size: 14px; font-family: LatoRegular, Regular, Lato, &quot;Lato 2&quot;, Arial, Helvetica, sans-serif\"><div><span id=\"x_62865384docs-internal-guid-db7bbb94-7fff-8c6a-af0c-dab621277131\"><span style=\"font-size: 11pt; font-family: Arial; background-color: transparent; font-variant-numeric: normal; vertical-align: baseline; white-space: pre-wrap\"><b><i><u><span class=\"x_62865384colour\" style=\"color: rgb(255, 0, 119)\"><span class=\"x_62865384highlight\" style=\"background-color: rgb(204, 238, 255)\"><div class=\"x_62865384target_moving\"><div class=\"x_62865384KB_Editor_ImageDiscBdr\" style=\"margin: 20px; border-radius: 3px; border: 1px solid rgb(238, 238, 238); display: inline-block\" id=\"x_62865384desc_img_14534151638440962\"><img src=\"https://desk.zoho.eu/support/ImageDisplay?downloadType=uploadedFile&amp;fileName=1660119998639.gif&amp;blockId=ca76ab1c619f743bbc6f7e12498e75ce694c04ff76014da7&amp;zgId=1a991909fd6bebe5fc0f13afecbc8bcf&amp;mode=view\" style=\"padding: 0px; max-width: 100%; box-sizing: border-box; width: 100px; height: auto\" data-zdeskdocid=\"img_14534151638440962\" class=\"x_62865384docsimage\" data-zdeskdocselectedclass=\"original\" /><span class=\"x_62865384KB_Editor_Quotedisc\" style=\"position: relative; display: block; text-align: left; padding: 0px 10px 10px; color: rgb(153, 153, 153)\"><span class=\"x_62865384inner\">perfect</span></span></div></div></span></span></u></i></b></span></span></div><div><span id=\"x_62865384docs-internal-guid-df9bc435-7fff-351e-54ac-06388395fa1e\"><span style=\"font-size: 11pt; font-family: Arial; background-color: transparent; font-variant-numeric: normal; vertical-align: baseline; white-space: pre-wrap\">$%#FYĐđצקЊกฃアィԱԳ😀🌍'&quot;’”‘’“”</span></span></div></div>",
        commented_time="2022-08-10T08:27:15.000Z"
    )
    yield comment


@pytest.fixture(scope="function")
def agent_data():
    Agent = namedtuple("Agent", "id name email")

    agent = Agent(
        id="115142000000092001",
        name="Milen",
        email="mivanov@siemplify.co"
    )
    yield agent

