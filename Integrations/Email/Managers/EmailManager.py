# -*- coding: utf-8 -*-
# ==============================================================================
# title           :EmailManager.py
# description     :This Module contain all Email cloud operations functionality
# author          :org@siemplify.co
# date            :2-5-18
# python_version  :2.7
# libraries       :BeautifulSoup, email, emaildata
# requirements    :
# product_version :
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
from EmailStringUtils import safe_str_cast
from base64 import b64decode, b64encode
from bs4 import BeautifulSoup
import email
import email.header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase
from email.header import Header
from email.utils import formataddr
from email import Encoders
from email import utils
import imaplib
import smtplib
from emaildata.text import Text
from emaildata.metadata import MetaData
import os
import re
import itertools
import socks
import ssl
import html2text
from urlparse import urlparse

# =====================================
#             CONSTANTS               #
# =====================================
OK_STATUS = 'OK'

HTML_IMAGE_TAG = "cstimage"
HTML_IMAGE_TAG_NAME_ATTR = "cid"
HTML_IMAGE_TAG_BASE64_ATTR = "base64image"
HTML_EMBEDED_IMAGES_FORMAT = """
<template>
    <cstImage cid="image1" base64Image ="iVBORw0KGgoAAAANSUhEUgAAAtYAAABOCAIAAACL2MaWAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAxvSURBVHhe7d1daBVnHsdxKwtt8cIWWWsFpUojpkRWidBgFrS5WIwX3aSw9HixaG6qwjaslGAFRWWFWtxSGwobdy80V2bpRaSFRITNKjRuimvjokuLgl0UXDdQMBdSA4L7j8/4MJ6X5zzzzDMz58x8P5TkzEmT8+KceX7zvPznucePHy8AAABI18LgOwAAQIqIIAAAIANEEAAAkAEiCAAAyAARBAAAZIAIAgAAMkAEAQAAGSCCAACADBBBAABABoLqqLfOTZzfMzD7nzvq3qaw+LUVq7d2rX23Z+WWzuAuAADQJIII8vmrbQ/uzai7mpeEkjU9297c9/6iZUuDuwAAQEMKIsjHz+W/zabXBACAxjEfQaaHhs/vGVDb+x43TV/IzNXr14f/euPsWJzxI8klb+7r37B7R7ANAABSMR9B9ChMa6n37TMn1Q+a0c2z45NHjv/v6vVg25Xkks5DA+t2loJtAADg23wE0aMwH/x052cvPK9u549brwnzSwAASMIzEaSJRmG8ePRw7vyegWunR4JtI8kiraXezkMDOU5pAACkptARpKqpY4MX9x8NNiosWduy7dTg8o72YBsAADghgtRhmF/CEhsAAJwRQWxdOz0ysffgw/uzwXbIomVL1/R0k0UAALBHBIngwb2Zsb7+W+cmgu0KZBEAACwRQdwZltiQRQAAMCOCeEAWAQAgKiKIT2QRACisa6dHJo8cj1OwOzUNUvKKCJIImzJoLKgBgNz4+vBxyR/BRjOTtim165YQQZJlk0XoIAGAJmVzkG9eSceR+QjyyYsrHj2ck43NHx3o+LBf/QB+WWaRN0q9FIMHgAZkcxhfvbWrd3S48YtoR7qkmkSQzkMDSTRM8xFkYu/Byyfmr04n79oHP0XOcb5GvxpkaCo1dfdmRmoAIHNz92cvn/jz9eGRus1ca6l326nBpr6Ih+G6JUm00fMRRB7ykxdXqO2oYzHhC/17VKg4UjeLyJvQse/9jb/fFWwDAJKnDs7SHlctSqnI8TmvI+mSDb7a/t6Ns+PB9hMSsNbtLPl6vfMRRL45TwfRF/pPgrzUzkMDxRkbMveMJT0mBwAw9HnkOG0Y1GqYvJwbu0cQeVp/23tA/yPFv9B/rdcpKeSXh/13tDQ+Q+8IcQQAPDKPtsghV1oiOfsPtgupso2O303gGEEe3JsZWtWuJrGK1lLv22fmZ5P4UvZSC5tChGFkrshvCwB4YZjOWMxuDzN1bjw9dFoHgL7piaXr29TtqIIIohfFWP4tPYNVJDQBR57PaO8OfUGWgp/3G4KIKNTUGQCIz9zNTJ+H2dSxwYv7j6rbktJ6R4fV7aiCCPLl9l3fjYzKDcu/paeAvDM63NLTre70riyFCM77ReXbokgKXL216+e/aFu5ZdMr69uef2lx8AMAQL25/ySPSOTNPLWhS912rugRRJDw37IZi0mtmlnl2T/FS4S5U0SRjxNregFATA8Nf/PxYNXkIXKwmDYTY339qhmSt86hoocIIoiIlCpSiyBK+Lzf+aXmWK2ZvGGSSCSLtPy6O7leKwBoEOYOD8E8j/ikaXau6KFkEEEkScgZvNotpF20nOEhL/Wzl1+Xr3Lb/rcKRT5yP35/c+Zf/747deXu1D/Ve1XphZcWr9ratWLzppVbNi1Z2xLcCwDNz5w88hE7DPNny0hbmfQ0wZj9ERlEkKFV7WXvneUMj/AcWMG8ELO6JwGC8wAAOWBzuMvHaIvHi+F5OZlvvggSnkmr2eQJOa1nXogzm4+oIvvl8o6NdJMAaHCGw1ouz6+SKEces6fEWwTR63Jt0kDMR1Xk4cIrOyx7NcK/xbwQB/KhvX1h8u4338rXqJVtZWdlQgmATNhcqyXfPbt6LarlxfBspgmGOfSLeIsg4WGOumnASwQRzilEzwuhIyQO+66RMkwoAZAadaS6VvtaLbkfU5Yw4bccuTSgtZZVShBZv2uHZcPqLYKUpQFz0+4rggi3FBLz6r4wUN0kdy5eun3hkuHiTBoTSgD4ZXlx2oIcfBItR16rp8SyTqm3CCLCacDctHuMIMIhhcivxFwLBAc2vSaSoKlHAiAqm9ghhxdpIIpWPSyFcuRCWtVwv4hkO5s6pT4jiLBs2iNNHLFRlkJshlf8xiBEYjOhRE5Q3ij1UjYegBnjLGbplCNX5N8izTql5RFE2PzFcCjzNRsjnEJshleIIA3CsmuEq9gACDMfOorZ4VFVyo1dpIfLJoJEjQuWLPtgFCJIYzIcVmRXkWMK04eBIjMcIogdVaXZ2IXX/do8XMzntjD4HpG0JXpFkOQG2aXU/TGpP4imtnR9W9enf9j9w5V3RodfeXY2k+wqF/cflV1W/hta1S47+u0Lk8HPAOTX3P3Zrw8fl0+9fPZPbei6fOJkOH8sWrZ0w+4d2/8+KscN8odH106PqPdcvlZd/FJJ1z1rLfWqGwaSV4JbrqpEEJ0DZI9RN6qS/62lZ5u67atYG/Kkpad75/SERGP5rzKOyAFIdt8zb/V+/mobWQTIq6fhY6M0E2XdHjp5/O6/13/1p+NMYK/KuZmXt32sr1+95/JV920YyGPpuX3bTg2qGwaR8kpVVQZiwvM8zMtyZkLzVhbHLvUqGS28j9bt1YnZ/4OUPeLqvkB+yaH76WL+ybKoUabgc0uj0nNR7dfilhURUaR1lpwXbNQQ9bF0K+xcp6RKBJGm4ovukjorrbssR1+rNyxSHKm6EMvm9RNBmpp5JhoHKaBhmT+8tTDPw03UZl4yRLiIiGUdVRGeBWL5WPFb4SoRRIS7N8x/2ubUNirJHzbrnokg+VA3i7CyF8iQfDAtuzdqIXzEEbWlcy4i4tDdklQEEbryh83e4yuIRHq/iCD5UyuOyC4heyCdIkCi3Lo3FPmQysfzyUUbOpd3tAf3IraoLZ1bEZHwBXjtu1vksdRt/xEknKTk2dgvu3WII24ZmQiSY3UPhbLPMGsEiE+O1ZUTRc0YJ01T1JbOoWUMD8HYd4HokPDK+rad00FZ0ahqRpCyJCERwUsVVI+IIEVQ90qPHA0BN3P3ZyeP/FGfatZC90aGbp2b+KI7ODlPLoLojhP7iSPCrbulTM0IoiRRBdUXIkhx2PQPk0UAs7oXYeFD1Gh0My8SiiAOQzDi9oXJM2/NL8Rd/NqK3T9cUXc6qBNBHj1bBbXr06Nxlt16FH7XiCAFZAglHEaBMubRlkjnvkiTzhM2S2qVSBEk3JLaD8GI83sGVMGSjg/7N390QN3poE4EEZJCPnv5dfmqNhthRMZt4Aq5RBZBwTlM5tBYq9LgHDr7LX+lbBguagzV3TO//cd4nOG5+hFETB0bvLj/aLCRdQqRz9vE3oPqgoqEd2g2M1iXd2x8MqS9acnaluBeoOHZDERaInM0l4QiyM2z42N9/fq6xFFb0nAvgP0Tq8oqgojwiIzIKoWEe42E/cAVisNy4gjlRtCwPGYOLVLJAzQIhwiiC2rUaqbDp/HC4Uxed4HEH4WwjSCiLIUICdRpXoG9LH/Yj42hmCyP4ynvxkClqWODV08OOwcO4kVeOUSQ8CKSumS3cegS088qfi9AhAgiKlOIkGcgaSvpxTLhnh/GX+BAEsnTIo+X9BmAJrsT1c+Qvh+/vznW1393yrSmgFlNheUQQao201U5n8Y7PKtaokUQIS8vXC9Ek1PJmJepM5i7P/uX1k6HhctAVYZyI4zRIDmWPXNkDihujX2tZlpz7jaTZCN/We+9GUSQsMrjuESQzkMDvo7dVWd6M/8DflWNI7KPpdC3h3yzn9LB/oaq9MQO81XrUxOuU+JlOWqsCCLMacu5a6Qsammrt3b9ZjxC6XfAkqG1YLIIarEPGQbLO9rllJRVWqj05fZd342Myo019a5anw7dK+Nr+lHcCKJIEPlq+3s3zo4H2wmQZkDOElhLhqSZS8LLfig5mB7yIosTOxhhQSSys+mr1ksLmG1RriQqgvqJIIr52O2Gmd5IX92RVMAGgQPxjfX162NRhinEuY6qmc8IUib+cZxlt2gESWRr5AMhA0mTljTzolzh/OF3RUiCEQTIHy9j/2hqxA6krCyFrNtZatvxbmq7X6IVMYggAAA0tLIUIiQKp1M+QK+CSaIiBhEEAIBGJynEsOwjodJc4SGYJCpiEEEAAGgOWY0Fe5yCGkYEAQCgyaQ5TT6JIRiFCAIAQBOLv/7UINHSGEQQAACQgYXBdwAAgBQRQQAAQAaIIAAAIANEEAAAkLoFC/4PifS74AZcr7wAAAAASUVORK5CYII=" />
    <cstImage cid="image2" base64Image ="iVBORw0KGgoAAAANSUhEUgAAAtYAAABOCAIAAACL2MaWAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAwDSURBVHhe7d1diBbXHcdxEwJJ8MKUUI2CUqWKhg1dMRBRQdkLUaGtT6FkFwqrN75cRCKyWMEQBSEtNjRZBI03ulfZXO0SwRWhi5auTQl2LRoaFGxZIRhLQS8kLizYfzLTk5N5OXNmzrw+8/1c6DOP67O7z8uc3/zP2zNPnz6dBwAAUK5n/b8BAABKRAQBAAAVIIIAAIAKEEEAAEAFiCAAAKACRBAAAFABIggAAKgAEQQAAFSACAIAACpABAEAABUgggAAgApUvEfMzfOjU8dPPvr3Pf/YwoKfLH3j8IG1+wb9YwAA0EDVRJAMySMOiQQAgCaqIIJMnxm5vH/IP8jJxneHNh3L+TGBVB7cuHVr5JPb4xdzydboenL5tGrnjjcOvzX/lYX+XUDLVBBBTi3ueXz/gX8wb96a/s6Oc8PPvfC8f2w092RW4svN86P+sYYUgtKQNlAEarpom7IjyF+OnZw6ftK7feibe5bJI44kkrHO4N1Lk96hfHQliHBJgXzl2G8IpCKhZFFvz49/1rNsywa58fxLC/x/ALpCqRFEzx9r+ju/+Pgj77aLQAqRTCMpZP1vD3iHQCqzDx99/sHZWyOjGQKHZN9VO7evfnPnsi0b/buAeHfGJ+R8+PWNW/5xSvTjoAuUFEEkIlzeP6RO6yu29XXGRhxLIIqkkAsDe26PT/jH1DORUtrkQdpA7gy9zDbkpCfnVd6TaJaSIog+/iPf/KGELyk2v3eUcgjMvFEdct5/8vCRf1eUVCOWgLzI+1POaf/5xxfy58yVKf/elKiXoLbKiCCB/pfiTuWBywj5Loe+of8e6UaPyvl647tDr+3q94+BWsrcj0O9BPVReAQpYvyHmQSR919c6t0+/PT7qTdoG5IH2sNllpa8+Zesf33p5g3Ltmx4efVK/16geMVGED1/FNT/Eun3z/j1RiJIC6Ua2MGoDnS9bPUSySWMqEPRCowg+hJkZeYPoSLIjnPDXNe2R9zADnIGoDjWS8glXcDyOk1e7qJHERUYQdQQ1Mz5I+5pSnxe3n9x6dyTWbnBcJAulvgpInkANiSUzFyZunf12syVa+Zx2ZFKaKiQi2xLHEkzunbfroJe3wIjiCpF2CxBlnZWpJDHjFsC5LPfDV89csK7TV9M9/HeLdc/PBt3upRzIgM7gMzcZwgTSupGHxeRgaHBdVFUBHl8/8GpxT3ebXMISGxOzOJm3jIcpPtIPPWu1e6MT0S+Wyh7AMXJlkuII3UQ3prN5jotPIoo9yXIi4ogkwff+fyDbye/LOrt2TXtL10advfS5IWBvYbwEfk06c+LRLOtp0+Gn0ciSBdI7LSm2gFULsNwV/nkMqakTC7jIgKvb77lkKIiiPqFfzU2snLndu/OAPmCM8vXeYM2RKrmRP7Xhz/6qWHABxGkuWx65QgfQG1ZhhL5FFMgKVpg/Ee2rdmkqdWXIJdH2Pev67m8akVFEJsEcHn/0PSZEbkhv8nm946mbU7MAz6IIE0UN6XFI+/7ZVs2frd6wcYl69f59wKoscQ4Ip/r4kY7tlyg/8VxaS55KT8d2KNXDdxLWZVFEP2pMVRKzAzfRU2KYZn2OjMXPOSUxNgOoMvImTk8poQgkrtAP0MuS5OrIRaKYwtbWQTRu6Z+PZFx3LXhu6hnSp5x5uXWkHkYMv0sQNeLLJDIZ18aBS483Kl+hkW9Pb/564Rj+FDCQ0NcWtjKIoj6gmxdUx7Dd5HoxzLt9WTobaHsAbRNXE+NnA0ki6z85fZsNfKWy6WfwUBaWDUcc/f05MJefwJsWkVFENUPIteym479YC6QJzGj2DA/SC7fArkwdLhQ8ABgGDLywksLlm/rYwubVHLpZzD7dGDvP0fH5IZcN3bGvi23ZFBUBNF7jCJTiMoHLj1JRJBGkDz+5yMnwjUPwgeAAPNUfEojNvQSiEs/g5m8UufW9nm3M++FUlQEmXsyO9YZvHvJXxEknDNUmUSkLeOEL6mJIPUkr9TU8T8Ehi/R2wIgkTmLUBoxUCUQmykwkle+/GR8UW9PhrHA7nuhFBVBhJ5Cwj+fPqXWXMaRR5BAF/kuVIggdRMebUrNA0AGkkVmrkx99be/y59eyxogDeer/R1m0yiq7UssgeirtstXpp2U5L4XSoERREgKMYwJ1cs4hu6YM8vXmfPH2n2DW08Hl77XK1FEkNLIO/LGRyPh12tFuVslA+hKhtKInF7kCofyqrC8/NZbSZ1cLtovGed4qV9sBBHmn+/i7gPe7PBwmUTRc5ZivqTW50M7LsYCS//98o68ml99dt0//j+KHwBy55VGInf3pShiGQvU5b2EttmHjwJjgaVRllN34kjNZkcQSQlqYo+0VXntGqDvUJPjfGiEGbrJCB8AShA5m0ZO+61d68wyFni9MKt2bv/5x2fl6Qo/jYbSgNLsCCICq625L2aql0CKmA8Nj8QOuQq5euSE3jtrGZwBIF+GPhq5HGrVcmf2sUDO3uGIJllELcSe2CI3PoLI7ymX0WqxXmnDHPe/0Usghk16kYrh460sWb9ux7lhRqcDqJBhiRHRhuqsYywQ9suLNz6CePQeGY+8UbJtomizSS8sGZYU08nnWcKHfwAAVTMEEWlW+/54IpdO/3pyjyB6i2wuhNQ9gqh5w4mLfwR6ZDwZCvvuzz6EV/aI27RWyEuzjH1rAdSeTRFXLnrX9HekuZEzm39XY+XSCFoWQuoeQVKt4RqXWy1LZ/Lf/3TwqHqTEUFSMX9K57OeGICGi5xfqXt59cod54abfk2VSwSZs9tnre4RRBo2tfhHqh8xEEcSS2f6KFTBXFxLiV0tbeg6BdAS0kboow8TNfEEmFdXgM3j1D2CCNUXk3a2S/i9IhFE3g2Ro0PkK6e/25hYSP6QJNsF9bRCmbtaKHsAaA85E04efCfyZChNieMkiZIRQX7AfmxtpMTSWQCjUA0MNQ8yB4A2e3z/wcXdB9TWZjppvBq0ykhpEUSesVOL/SGe9Y0gepdStv305BEuDOy5PT7hH8crbmPiRjOP86CrBQDCwpMk5GyZbapmmXKJIDabnKjnJ/MSGGVEEKH6YrIVQjzm2d6C/hfFZjItZQ8AMItsd6SVkcu22q7BmEsEsdlu130JjJIiiN6ZknZrfqTihQ99i9oAah4AkEpkEKltRcQ9gtw8P3pxtx+wDsVvt+v+jUqKICLV7FzYsJns7qHgAQDuJIuoxcs9NRwmorodJCRl2HlN38FfGOJFkyKIPjvXfSOYdrLPHIJqBwDkLnKGhAQROdnW5DIvMIRFGoJNxyI25Y8UyB8SX7ae/v5Q5z4WVZQXQYTN1vwQqaJGGOEDAIoW2Tsz/5WFr/Z3qi2KzKVc+yTSim19nbGRuC4YoRbCcNmOrdQIIs+LzWprreKSNuheAYBqmedJZOsKyYU0uGOdwcg5xokS84deLHFZCKPUCCJUH1Wq0lCjSbaYuTJ17+o1+TNbVUMhcwBADZkvJqtq77KVQxLnlur5w3EhjLIjiN5H1ZUpxHJrWTOiBgA0UVxR5LVd/T2Db3bBKV1fLySxWJKo7AgSLg01feCCY+YgbQBAVwq3d3LCr3ykiAv5XS4M7PVWfHDPH6LsCCIiO6gq7DCz4ZIz5BWSeMGm9gDQNtLehZf2lkZBLrybOC1UrUUmDOuF2Ksggoi4DqrKg4gEI/nBHEdsMCEFAKAYRopIe1H/Fd8VtRCIYbJuKtVEECVuC7pyXhXHua8KmQMAkChupMhzdVpWJE4uC4EEVBxBPHFFkVohZwAAHJnbu9oOFpEfWMKTd7nushBIQC0iiKc+QSSvEhMAAAZxdRG56F2xra8mdZHAkqkuC4EE1CiC6MyLveRFYiazUQAA1TKMCpB2av3ht15/e69/XDp9Fq5wXAgkoKYRBACAtjEURcoftap3vohcZuEGEEEAAKgXry4yfeb8nLYrryghi8QtQpHLLNwAIggAAHUUN2k095VFEte+KmiIJBEEAIBaK2d8ZFjifjGOiCAAADRDOVmktEUoiCAAADRGQQtYVLL2FREEAABU4Fn/bwAAgBIRQQAAQAWIIAAAoAJEEAAAUAEiCAAAqAARBAAAVIAIAgAASjdv3v8Awz0IQ6J9YzEAAAAASUVORK5CYII=" />
    <html>
    <head>
        <style type="text/css">
        .title {
            color: blue;
            text-decoration: bold;
            text-size: 1em;
        }

        .author {
            color: gray;
        }
        </style>
    </head>
    <body>
        <img alt="StartHeader" src="cid:image1" />
        <span class="title">La super bonne</span>
        This is the message body
        </h1>
        <br/>
        <img alt="EndHeader" src="cid:image2" />
    </body>
    </html>
</template>
"""

EMAIL_PATTERN = "(?<=<)(.*?)(?=>)"
ANSWER_PLACEHOLDER_PATTERN = "(?<={{)[^{]*(?=}})"
ENCODING_MAPPING = {
    "iso-8859-8-i": "iso-8859-8"
}

MAIL_SUBJECT_KEY = 'subject'

SIEMPLIFY_MAIL_DICT_HTML_BODY_KEY = 'html_body'
SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY = 'plaintext_body'
SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY = 'body'
SIEMPLIFY_MAIL_DICT_RAW_EML_KEY = 'raw'
SIEMPLIFY_MAIL_DICT_DATE_KEY = 'date'
SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY = 'unixtime_date'
SIEMPLIFY_MAIL_DICT_EMAIL_ID_KEY = 'email_uid'
SIEMPLIFY_MAIL_DICT_ASNWER_ID_KEY = 'answer'


# =====================================
#              CLASSES                #
# =====================================


class RFC3501FlagsEnum(object):
    SEEN = '\\SEEN'
    DELETED = '\\DELETED'


class EmailManagerError(Exception):
    """
    General Exception for Email manager
    """
    pass


class ProxyIMAP4(imaplib.IMAP4):
    def __init__(self, host='', port=imaplib.IMAP4_PORT,
                 proxy_type=socks.PROXY_TYPE_SOCKS5, proxy_addr=None,
                 proxy_port=None, proxy_username=None, proxy_password=None):
        self.proxy_type = proxy_type
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        imaplib.IMAP4.__init__(self, host, port)

    def open(self, host,port=imaplib.IMAP4_PORT):
        self.host = host
        self.port = port
        self.sock = socks.create_connection(dest_pair=(host, port),
                                            proxy_type=self.proxy_type,
                                            proxy_addr=self.proxy_addr,
                                            proxy_port=self.proxy_port,
                                            proxy_username=self.proxy_username,
                                            proxy_password=self.proxy_password)
        self.file = self.sock.makefile('rb')


class ProxyIMAP4SSL(imaplib.IMAP4_SSL):
    def __init__(self, host='', port=imaplib.IMAP4_SSL_PORT, keyfile=None,
                 certfile=None, proxy_type=socks.PROXY_TYPE_SOCKS5,
                 proxy_addr=None, proxy_port=None, proxy_username=None,
                 proxy_password=None):
        self.proxy_type = proxy_type
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        imaplib.IMAP4_SSL.__init__(self, host, port, keyfile, certfile)

    def open(self, host, port=imaplib.IMAP4_SSL_PORT):
        self.host = host
        self.port = port
        #actual privoxy default setting, but as said, you may want to parameterize it
        self.sock = socks.create_connection(dest_pair=(host, port),
                                            proxy_type=self.proxy_type,
                                            proxy_addr=self.proxy_addr,
                                            proxy_port=self.proxy_port,
                                            proxy_username=self.proxy_username,
                                            proxy_password=self.proxy_password)
        self.sslobj = ssl.wrap_socket(self.sock, self.keyfile, self.certfile)
        self.file = self.sslobj.makefile('rb')


class ProxySMTP(smtplib.SMTP):
    def __init__(self, host='', port=smtplib.SMTP_PORT,
                 proxy_type=socks.PROXY_TYPE_SOCKS5, proxy_addr=None,
                 proxy_port=None, proxy_username=None, proxy_password=None):
        self.proxy_type = proxy_type
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        smtplib.SMTP.__init__(self, host, port)

    def _get_socket(self, host, port, timeout):
        # This makes it simpler for SMTP_SSL to use the SMTP connect code
        # and just alter the socket connection bit.
        return socks.create_connection(dest_pair=(host, port),
                                       proxy_type=self.proxy_type,
                                       proxy_addr=self.proxy_addr,
                                       proxy_port=self.proxy_port,
                                       proxy_username=self.proxy_username,
                                       proxy_password=self.proxy_password,
                                       timeout=timeout)


class ProxySMTPSSL(smtplib.SMTP_SSL):
    def __init__(self, host='', port=smtplib.SMTP_SSL_PORT, keyfile=None,
                 certfile=None, proxy_type=socks.PROXY_TYPE_SOCKS5,
                 proxy_addr=None, proxy_port=None, proxy_username=None,
                 proxy_password=None):
        self.proxy_type = proxy_type
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        smtplib.SMTP_SSL.__init__(self, host, port, keyfile, certfile)

    def _get_socket(self, host, port, timeout):
        new_socket = socks.create_connection(dest_pair=(host, port),
                                             proxy_type=self.proxy_type,
                                             proxy_addr=self.proxy_addr,
                                             proxy_port=self.proxy_port,
                                             proxy_username=self.proxy_username,
                                             proxy_password=self.proxy_password,
                                             timeout=timeout)
        new_socket = ssl.wrap_socket(new_socket, self.keyfile, self.certfile)
        self.file = smtplib.SSLFakeFile(new_socket)
        return new_socket


class EmailManager(object):
    """
    Responsible for all Email system operations functionality
    """

    def __init__(self, mail_address, proxy_server=None, proxy_username=None, proxy_password=None):
        self.mail_address = mail_address

        if proxy_server:
            server_url = urlparse(proxy_server)
            scheme = server_url.scheme

            if scheme and server_url.hostname:
                self.proxy_addr = "{}://{}".format(scheme, server_url.hostname)
                self.proxy_port = server_url.port
            else:
                if ":" in proxy_server:
                    self.proxy_addr = proxy_server.split(":")[0]
                    self.proxy_port = int(proxy_server.split(":")[1])
                else:
                    self.proxy_addr = proxy_server
                    self.proxy_port = None

            self.proxy_username = proxy_username
            self.proxy_password = proxy_password

        else:
            self.proxy_addr = None
            self.proxy_port = None
            self.proxy_username = None
            self.proxy_password = None

        self.smtp = None
        self.imap = None

    def login_smtp(self, host, port, username="", password="", use_ssl=False, use_auth=False):
        if self.proxy_addr:
            self.smtp = ProxySMTPSSL(
                host=host,
                port=int(port),
                proxy_addr=self.proxy_addr,
                proxy_port=self.proxy_port,
                proxy_username=self.proxy_username,
                proxy_password=self.proxy_password
            ) if use_ssl else ProxySMTP(
                host=host,
                port=int(port),
                proxy_addr=None,
                proxy_port=None,
                proxy_username=None,
                proxy_password=None
            )
        else:
            self.smtp = smtplib.SMTP_SSL(host=host, port=int(
                port)) if use_ssl else smtplib.SMTP(host=host, port=int(port))
        self.smtp.ehlo()
        # Try to start TLS
        try:
            self.smtp.starttls()
        except:
            print "The server does not support TLS protocol"
        if use_auth:
            try:
                self.smtp.login(username, password)
            except Exception as error:
                raise EmailManagerError(
                    "Cannot login to SMTP Server with given creds, error: {0}".format(error.message))
        return True

    def login_imap(self, host, port, username, password, use_ssl=False):
        if self.proxy_addr:
            self.imap = ProxyIMAP4SSL(
                host=host, port=int(port),
                proxy_addr=self.proxy_addr,
                proxy_port=self.proxy_port,
                proxy_username=self.proxy_username,
                proxy_password=self.proxy_password
            ) if use_ssl else ProxyIMAP4(
                host=host, port=int(port),
                proxy_addr=self.proxy_addr,
                proxy_port=self.proxy_port,
                proxy_username=self.proxy_username,
                proxy_password=self.proxy_password
            )
        else:
            self.imap = imaplib.IMAP4_SSL(host=host, port=int(
                port)) if use_ssl else imaplib.IMAP4(host=host, port=int(port))
        try:
            self.imap.login(username, password)
            self.imap.select()
        except Exception as error:
            raise EmailManagerError("Cannot login to IMAP serve with the given creds, error: {}".format(error.message))
        return True

    def send_mail(self, to_addresses, subject, body):
        """
        Send mail using smtp
        :param to_addresses: {string} concated string list of adresses to send to the mail
        :param subject: {string}
        :param body: {string}
        :return: {boolean}
        """
        if not self.smtp:
            raise EmailManagerError("Smtp Server is no configured yet, call first to self.login_smtp()")

        msg = MIMEText(body, 'plain', 'utf-8')
        msg['From'] = self.mail_address
        msg['To'] = to_addresses
        msg['Subject'] = subject
        try:
            self.smtp.sendmail(self.mail_address, to_addresses.split(','), msg.as_string())
        except Exception as error:
            raise EmailManagerError("sendmail: {}".format(error))
        return True

    def send_mail_with_attachment(self, to_addresses, subject, body, attachment_string, file_name):
        """
        Send mail using smtp with file attachment.
        :param to_addresses: {string} concated string list of adresses to send to the mail {string}
        :param subject: The subject of the mail {string}
        :param body: The body of the mail {string}
        :param attachment_string: The content of the attached file. {string}
        :return: if succeed {boolean}
        """
        if not self.smtp:
            raise EmailManagerError("Smtp Server is no configured yet, call first to self.login_smtp()")

        msg = MIMEMultipart()
        msg['From'] = self.mail_address
        msg['To'] = to_addresses
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'html', 'utf-8'))

        if attachment_string:
            part = MIMEBase('application', "octet-stream")
            part.set_payload(attachment_string)
            Encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="{0}"'.format(file_name))

            msg.attach(part)

        try:
            self.smtp.sendmail(self.mail_address, to_addresses.split(','), msg.as_string())
        except Exception as error:
            raise EmailManagerError("sendmail: {}".format(error))
        return True

    def send_mail_html_embedded_photos(self, to_addresses, subject, html_body, cc=None, bcc=None, display_sender_name=None):
        """
        Send mail using smtp with embedded photos in it according to html template (Example above in consts)
        :param to_addresses: {string} concated string list of addresses to send to the mail
        :param subject: {string}
        :param html_body: {string} html format
        :return: {boolean}
        """
        if not self.smtp:
            raise EmailManagerError("Smtp Server is no configured yet, call first to self.login_smtp()")

        msg = MIMEMultipart('related')

        # if set send the mail when only the sender name appear on the inbox
        if display_sender_name:
            sender = formataddr((str(Header(display_sender_name, 'utf-8')), self.mail_address))
        else:
            sender = self.mail_address

        msg['From'] = sender
        msg['To'] = to_addresses
        msg['Subject'] = subject
        msg_id = email.utils.make_msgid()
        msg['Message-ID'] = msg_id

        # Email headers don't matter to the SMTP server. Just add the CC and BCC recipients to the toaddrs.
        # For CC, add them to the CC header.
        if cc:
            msg['CC'] = cc
            cc = cc.split(",")
        else:
            cc = []

        # Not adding header - msg['bcc'] will just add a bcc header to your email which defeats the point of bcc!
        # The bcc recipients will all receive the email, but the email clients won't display them as recipients.
        if bcc:
            bcc = bcc.split(",")
        else:
            bcc = []

        toaddrs = to_addresses.split(',') + cc + bcc

        soup = BeautifulSoup(html_body)
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        # Extract cstimage tags images from html template
        for cst_tag in soup.findAll(HTML_IMAGE_TAG):
            image_name = cst_tag[HTML_IMAGE_TAG_NAME_ATTR]
            image_content = b64decode(cst_tag[HTML_IMAGE_TAG_BASE64_ATTR])
            img = MIMEImage(image_content, image_name)
            img.add_header('Content-ID', '<{}>'.format(image_name))
            img.add_header('Content-Disposition', 'inline', filename=image_name)
            msg.attach(img)

        try:
            self.smtp.sendmail(msg['From'], toaddrs, msg.as_string())
        except Exception as error:
            raise EmailManagerError("sendmail: {}".format(error))
        return msg_id

    def get_imap_folder_list(self):
        """
        Get all mail account folders
        :return: {string list}
        """
        if not self.imap:
            raise EmailManagerError("Imap Server is no configured yet, call first to self.login_imap()")

        result, mailboxes = self.imap.list()
        if result != OK_STATUS:
            raise EmailManagerError("get_imap_folder_list(): {}".format(mailboxes))

        return [m.split(' "/" ')[1].replace('"', '') for m in mailboxes]

    def extract_attachments(self, email_uid, encode_as_base64=False, convert_utf8=False):
        """
        Get attachment name and content from email
        :param email_uid: the uid of the email
        :param encode_as_base64: {bool} Whether to encode the attachments content with base64 or not
        :param convert_utf8: {bool} Whether to convert the filename to utf8 (False to prevent regression)
        :return: {dict} attachment name and his content
        """
        # Fetch an email but do not mark it as seen
        result, data = self.imap.uid('fetch', email_uid, "(BODY.PEEK[])")

        if result != OK_STATUS:
            raise EmailManagerError("receive_mail(): ERROR getting message {0}".format(email_uid))

        # Return a message object structure from a string.
        msg = email.message_from_string(data[0][1])
        return self._extract_attachments_from_msg(msg, encode_as_base64=encode_as_base64, convert_utf8=convert_utf8)

    @staticmethod
    def is_attachment(mime_part, include_inline=False):
        """
        Determine if a MIME part is a valid attachment or not.
        Based on :
        https://www.ietf.org/rfc/rfc2183.txt
        More about the content-disposition allowed fields and values:
        https://www.iana.org/assignments/cont-disp/cont-disp.xhtml#cont-disp-1
        :param mime_part: {email.message.Message} The MIME part
        :param include_inline: {bool} Whether to consider inline attachments as well or now
        :return: {bool} True if MIME part is an attachment, False otherwise
        """
        # Each attachment should have the Content-Disposition header
        content_disposition = mime_part.get("Content-Disposition")

        if not content_disposition or not isinstance(content_disposition, basestring):
            return False

        # "Real" attachments differs from inline attachments (like images in signature)
        # by having Content-Disposition headers, that starts with 'attachment'.
        # Inline attachments have the word 'inline' at the beginning of the header.
        # Inline attachments are being displayed as part of the email, and not as a separate
        # file. In most cases, the term attachment is related to the MIME parts that start with
        # 'attachment'.
        # The values are not case sensitive
        if content_disposition.lower().startswith("attachment"):
            return True

        if include_inline and content_disposition.lower().startswith("inline"):
            return True

        return False

    def extract_filename(self, mime_part, convert_utf8=False):
        """
        Extract the filename of an attachment MIME part
        :param mime_part: {email.message.Message} The MIME part
        :param convert_utf8: {bool} Whether to convert the filename to utf8
        :return: {str} The decoded filename
        """
        # This is based on email.get_filename() method. The original method decodes
        # the header according to rfc2231, but its not consistent on the return value
        # (sometimes its str, if all the text is ASCII, and otherwise its unicode).
        missing = object()

        filename = mime_part.get_param('filename', missing, 'content-disposition')

        if filename is missing:
            filename = mime_part.get_param('name', missing, 'content-disposition')

        if filename is missing:
            return

        return self.decode_header_value(filename, convert_utf8)

    def _extract_attachments_from_msg(self, msg, encode_as_base64=False, convert_utf8=True):
        """
        Extract the attachments from a Message object
        :param msg: {Message} the msg to extract from
        :param encode_as_base64: {bool} Whether to encode the attachments content with base64 or not
        :param convert_utf8: {bool} Whether to convert the filename to utf8
        :return: {dict} The extracted attachments (filename: content)
        """
        attachments_dict = {}

        if msg.is_multipart():
            attachments = msg.get_payload()

            for attachment in attachments:
                if self.is_attachment(attachment):
                    # Extract filename from attachment
                    filename = self.extract_filename(attachment, convert_utf8=True)

                    # Some emails can return an empty attachment.
                    # Validate that the attachment has a filename
                    if filename:
                        # Get attachment content - decode to raw
                        file_content = attachment.get_payload(decode=True)

                        # In case of EML file - probably bug.
                        # TODO: This might be problematic. As .eml attachment (content-type of messade/rfc822)
                        # TODO: are considered multipart, then get_payload() will return None.
                        # TODO: The extraction of file_data is correct, and in most cases
                        # TODO: it will be encoded with base64, but it's not guaranteed,
                        # TODO: so we might have to extract the Content-Transfer-Encoding
                        # TODO: and parse accordingly.
                        if not file_content and '.eml' in filename:
                            file_data = attachment.get_payload()[0]
                            file_content = b64decode(file_data.get_payload())

                        if encode_as_base64:
                            file_content = b64encode(file_content)

                        attachments_dict.update({filename: file_content})

        return attachments_dict

    @staticmethod
    def save_attachment_to_local_path(path, attachment_name, attachment_content):
        """
        Save message attachment to local path
        :param path: {string}
        :param attachment_name: {string} file name
        :param attachment_content: file content
        :return: path to the downloaded files
        """
        a = attachment_name
        local_path = os.path.join(path, a)
        with open(local_path, 'wb') as f:
            f.write(attachment_content)
        return local_path

    def extract_html_body(self, msg):
        """
        extract html body from mail
        :param msg: {Message}
        :return: mail html body
        """
        html_body = ""
        if not msg.is_multipart():
            content_type = msg.get_content_type()
            if content_type == "text/html":
                html_body += msg.get_payload(decode=True)
            return html_body
        for part_msg in msg.get_payload():
            # part is a new Message object which goes back to extract_content
            part_html_body = self.extract_html_body(part_msg)
            html_body += part_html_body

        return html_body

    @staticmethod
    def _build_html_2_text_obj():
        """
        Create a HTML2Text object
        :return: {html2text.HTML2Text} The HTMl2Text object
        """
        html_renderer = html2text.HTML2Text()
        # Configuration was decided by Product Team
        html_renderer.ignore_tables = True
        html_renderer.protect_links = True
        html_renderer.ignore_images = False
        html_renderer.ignore_links = False
        return html_renderer

    @staticmethod
    def render_html_body(html_body):
        """
        Render html body to plain text plain
        :param html_body: {str} The HTML body of the email
        :return: {str} Plain text rendered HTML
        """
        try:
            html_renderer = EmailManager._build_html_2_text_obj()
            return html_renderer.handle(html_body)

        except Exception:
            # HTML2Text is not performing well on non-ASCII str. On failure - try to decode the str to unicode
            # using utf8 encoding. If failed - return a proper message.
            try:
                # HTML2Text object shouldn't be used twice - it can cause problems and errors according to google
                # Therefore rebuild the object
                html_renderer = EmailManager._build_html_2_text_obj()
                html_body = html_body.decode("utf8")
                # Encode back to utf8
                return html_renderer.handle(html_body).encode("utf8")
            except Exception as e:
                return "Failed rendering HTML. Error: {}".format(str(e))

    def get_message_data_by_message_id(self, email_uid, mark_as_read=False, delete_mail=False, include_raw_eml=False,
                                       convert_body_to_utf8=False, convert_subject_to_utf8=False):
        """
        Get mails data using message id
        :param mark_as_read: {boolean} mark mails as read after fetching them, Default is False
        :param delete_mail: {boolean} delete mails from folder after fetching them, Default is False
        :param email_uid: {string}
        :param include_raw_eml: {boolean} get the mail eml (in eml format)
        :param convert_body_to_utf8: {boolean} Return message body as utf-8 encoded str(Avoid regression).
        :param convert_subject_to_utf8: {boolean} Return message subject as utf-8 encoded str(Avoid regression).
        :return: {Mail object}
        """
        result, data = self.imap.uid('fetch', email_uid, '(RFC822)')
        if result != OK_STATUS:
            raise EmailManagerError("receive_mail(): ERROR getting message {0}".format(email_uid))

        self.mark_email_as_read(email_uid, mark_as_read=mark_as_read)

        if delete_mail:
            self.delete_mail(email_uid)

        msg = email.message_from_string(data[0][1])
        metadata = self.build_siemplify_message_object(msg, include_raw_eml, convert_body_to_utf8,
                                                       convert_subject_to_utf8, email_uid)
        return metadata

    @staticmethod
    def extract_unixtime_date_from_msg(msg, default_value=1):
        """
        Extract the date of the msg in unixtime
        :param msg: {email.message.Message} The msg object
        :param default_value: {long} The default value to return on failure. If not passed (None, 0, any False value) - an exception will be raised on failure.
        :return: {long} The unixtime of the message. If failed parsing - return 1.
        """
        try:
            date_str = msg.get('date')

            if date_str:
                date_tuple = email.utils.parsedate_tz(date_str)
                if date_tuple:
                    # Returns time in seconds, not in milliseconds
                    return email.utils.mktime_tz(date_tuple) * 1000

                if default_value:
                    return default_value

                raise EmailManagerError("Unable to extract unixtime from message. No date tuple could be parsed.")

            if default_value:
                return default_value

            raise EmailManagerError("Unable to extract unixtime from message. No date field provided.")

        except Exception:
            if default_value:
                return default_value
            raise

    def build_siemplify_message_object(self, msg, include_raw_eml=False, convert_body_to_utf8=False,
                                       convert_subject_to_utf8=False, email_uid=None):
        """
        Create a Siemplify message object from a given msg object. The method is parsing the email.Message object
        relevant data and created a dict in Siemplify format.
        :param msg: {email.message.Message} The msg object
        :param include_raw_eml: {boolean} get the mail eml (in eml format)
        :param convert_body_to_utf8: {boolean} Return message body as utf-8 encoded str(Avoid regression).
        :param convert_subject_to_utf8: {boolean} Return message subject as utf-8 encoded str(Avoid regression).
        :param email_uid: {int} The uid of the email (in case the email was fetched from an IMAP server, like gmail)
        :return: {dict} The mail data
        """
        extractor = MetaData(msg)

        # Start building "siemplify mail dict". base it on "email library dict"
        mail_dict = extractor.to_dict()
        mail_dict[SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY] = self.extract_unixtime_date_from_msg(msg)
        mail_dict[MAIL_SUBJECT_KEY] = self.extract_subject(msg, convert_subject_to_utf8)
        mail_dict[SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY] = self.extract_content(msg, convert_body_to_utf8)[0]
        mail_dict[SIEMPLIFY_MAIL_DICT_HTML_BODY_KEY] = self.extract_content(msg, convert_body_to_utf8)[1]
        mail_dict[SIEMPLIFY_MAIL_DICT_EMAIL_ID_KEY] = email_uid

        if mail_dict[SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY]:
            mail_dict[SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY] = mail_dict[SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY]
        else:
            # Can't know the original charset of the body - try and hope for the best.
            mail_dict[SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY] = self.render_html_body(mail_dict[SIEMPLIFY_MAIL_DICT_HTML_BODY_KEY])

        # Try extracting the answer
        try:
            match = re.search(ANSWER_PLACEHOLDER_PATTERN, mail_dict[SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY])
            if match:
                mail_dict[SIEMPLIFY_MAIL_DICT_ASNWER_ID_KEY] = match.group()
            else:
                mail_dict[SIEMPLIFY_MAIL_DICT_ASNWER_ID_KEY] = ""
        except Exception:
            mail_dict[SIEMPLIFY_MAIL_DICT_ASNWER_ID_KEY] = ""

        if include_raw_eml:
            # original message as string
            mail_dict['original_message'] = msg.as_string()

        return mail_dict

    def receive_mail_ids(self, folder_name='Inbox', subject_filter=None, content_filter=None, time_filter=None,
                         only_unread=False, message_id=None, reply_to=None):
        """
        Get mails from account folder using filters, Cannot filter with unicode string!
        :param folder_name: {string} Default is Inbox folder
        :param subject_filter: {string} Default is None
        :param content_filter: {string} Default is None
        :param time_filter: {datetime object} Default is None
        :param only_unread: {boolean} Fetch only unread mails, Default is False
        :param message_id: {string}
        :return: {list} Messages uids
        """
        if not self.imap:
            raise EmailManagerError("Imap Server is no configured yet, call first to self.login_imap()")

        result, data = self.imap.select(folder_name)

        if result != OK_STATUS:
            raise EmailManagerError("Folder {} not found ".format(folder_name))

        # Filtering emails - Create the imap query
        filters = []
        if only_unread:
            filters.append("NOT SEEN")
        if subject_filter:
            filters.append("SUBJECT \"{}\"".format(subject_filter))
        if content_filter:
            filters.append("BODY \"{}\"".format(content_filter))
        if time_filter:
            filters.append("SINCE {}".format(time_filter.strftime("%d-%b-%Y")))
        if message_id:
            filters.append("HEADER Message-ID {}".format(message_id))

        if reply_to:
            filters.append("HEADER In-Reply-To {}".format(reply_to))

        if filters:
            where = "({0})".format(" ".join(filters))
        else:
            where = "ALL"

        result, all_data = self.imap.uid('search', None, '{0}'.format(where))
        if result != OK_STATUS:
            raise EmailManagerError(
                "Error in receive_mail() finding messages. {}: {}".format(
                    unicode(result).encode("utf-8"),
                    unicode(all_data).encode("utf-8")))

        return all_data[0].split()

    def mark_email_as_read(self, email_uid, mark_as_read=True):
        """
        Mark specific email as read/unread
        :param email_uid: {String}
        :param mark_as_read: {Boolean}
        """
        if mark_as_read:
            self.imap.uid('store', email_uid, '+FLAGS', RFC3501FlagsEnum.SEEN)
        else:
            self.imap.uid('store', email_uid, '-FLAGS', RFC3501FlagsEnum.SEEN)

    def delete_mail(self, email_uid):
        """
        Deletes a specific email
        :param email_uid: {String}
        """
        self.imap.uid('store', email_uid, '+FLAGS', RFC3501FlagsEnum.DELETED)

    # DEPRECATED - USED ONLY FOR EML CONNECTOR! #
    def parse_eml(self, eml_content, convert_body_to_utf8=False, convert_subject_to_utf8=False,
                  encode_attachments_as_base64=True, convert_filenames_to_utf8=True):
        """
        Extracts all data from e-mail, including sender, to, etc., and returns
        it as a dictionary
        :param eml_content: {email.message.Message} An eml object
        :param convert_body_to_utf8: {boolean} Return message body as utf-8 encoded str(Avoid regression).
        :param convert_subject_to_utf8: {boolean} Return message subject as utf-8 encoded str(Avoid regression).
        :param convert_filenames_to_utf8: {boolean} Return message filenames as utf-8 encoded str.
        :param encode_attachments_as_base64: {boolean} Whether to encode the attachments content with base64.
        :return: {dict} The data of the eml
        """
        msg = email.message_from_string(eml_content)
        metadata = self.build_siemplify_message_object(msg, convert_body_to_utf8=convert_body_to_utf8,
                                                       convert_subject_to_utf8=convert_subject_to_utf8)

        to = metadata.get("to")
        cc = metadata.get("cc")
        bcc = metadata.get("bcc")

        recipients = [recipient for recipient in itertools.chain(to, cc, bcc)]
        metadata["Recipients"] = ", ".join(recipients)

        return {
            "subject": metadata.get("subject"),
            "from": metadata.get("sender"),
            "to": ",".join(metadata.get("to", [])),
            "CC": ",".join(metadata.get("cc", [])),
            "BCC": ",".join(metadata.get("bcc", [])),
            "Recipients": ", ".join(recipients),
            "Date": metadata.get("date").isoformat(),
            "body": metadata.get(SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY),
            "plaintext_body": metadata.get(SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY),
            "HTML Body": metadata.get(SIEMPLIFY_MAIL_DICT_HTML_BODY_KEY),
            "Attachments": self._extract_attachments_from_msg(msg, encode_as_base64=encode_attachments_as_base64,
                                                              convert_utf8=convert_filenames_to_utf8),
            SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY: metadata.get(SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY)
        }

    @staticmethod
    def extract_metadata(msg):
        """
        Extract metadata (sender, recipient, date and subject) from EML
        :param msg: {email.message.Message} An eml object
        :return: (tuple) sender, recipient, date and subject
        """
        return re.findall(EMAIL_PATTERN, msg.get("from", "").strip()), \
               re.findall(EMAIL_PATTERN, msg.get("to", "").strip()), \
               re.findall(EMAIL_PATTERN, msg.get("cc", "").strip()), \
               re.findall(EMAIL_PATTERN, msg.get("bcc", "").strip()), \
               msg.get("subject", "").strip(), \
               msg.get("date", "").strip()

    @staticmethod
    def fetch_message_charset(message):
        """
        Fetch the charset of the payload of the message.
        :param message: {Message} Message object.
        :return: {string} Payload charset.
        """
        charset = message.get_content_charset()

        if charset in ENCODING_MAPPING:
            return ENCODING_MAPPING.get(charset)
        return charset

    def extract_subject(self, msg, convert_utf8=False):
        """
        Extract message subject from email message.
        :param msg: {Message} Message object.
        :param convert_utf8: {bool} True to convert subject to utf-8 encoded string.
        :return: {string} Subject text.
        """
        raw_subject = msg.get(MAIL_SUBJECT_KEY)
        return self.decode_header_value(raw_subject, convert_utf8)

    @staticmethod
    def decode_header_value(header_value, convert_utf8=False):
        """
        Extract message header value from email message.
        :param header_value: {str} The raw header value.
        :param convert_utf8: {bool} True to convert value to utf-8 encoded string.
        :return: {string} The parsed header value.
        """
        try:
            parsed_value, encoding = email.Header.decode_header(header_value)[0]
            if convert_utf8:
                return safe_str_cast(parsed_value, current_encoding=encoding)
            return parsed_value.decode(encoding)

        except:
            return header_value

    def extract_content(self, msg, convert_body_to_utf8=False):
        """
        Extracts content from an e-mail message.
        :param msg: {email.message.Message} An eml object
        :param convert_body_to_utf8: {bool} True to return body as ut8 encoded string(Avoid regression).
        :return: {tuple} Text body, Html body, files dict (file_name: file_hash),
        count of parts of the emails
        """
        html_body = ""
        text_body = ""
        count = 0

        if not msg.is_multipart():
            # Not an attachment!
            # See where this belong - text_body or html_body
            content_type = msg.get_content_type()
            message_payload = msg.get_payload(decode=True)

            if convert_body_to_utf8:
                message_encoding = self.fetch_message_charset(msg)
                message_payload = safe_str_cast(message_payload, current_encoding=message_encoding)

            if content_type == "text/plain":
                text_body += message_payload
            elif content_type == "text/html":
                html_body += message_payload

            return text_body, html_body, 1

        # This IS a multipart message.
        # So, we iterate over it and call extract_content() recursively for
        # each part.
        for part_msg in msg.get_payload():
            # part is a new Message object which goes back to extract_content
            part_text_body, part_html_body, part_count = self.extract_content(
                part_msg)
            text_body += part_text_body
            html_body += part_html_body
            count += part_count

        return text_body, html_body, count
