#!/usr/local/qualitia/bin/python3

from email.message import EmailMessage
from email.parser import BytesParser, Parser
from email.policy import default
from email.utils import parseaddr, parsedate_to_datetime
from datetime import datetime, timezone, timedelta
import sys
import os
import dkim

JST = timezone(timedelta(hours=9), "JST")


def get_info(eml):
    with open(eml, 'rb') as fp:
        headers = BytesParser(policy=default).parse(fp)

    display_name, from_addr = parseaddr(headers["From"])

    dkim_verify = "none"
    dkim_d = None
    if "DKIM-Signature" in headers:
        with open(eml, 'rb') as fp:
            dkim_verify = "pass" if dkim.verify(fp.read()) else "fail"

        dkim_params = [_.replace("\t", "").replace(" ", "") for _ in headers["DKIM-Signature"].split(";")]
        for dkim_param in dkim_params:
            if dkim_param.startswith("d="):
                dkim_d = dkim_param
                break

    subject = headers["subject"]
    to = headers["to"]
    if not to:
        to = ""

    if "date" in headers:
        date = datetime.fromtimestamp(parsedate_to_datetime(headers["date"]).timestamp(), JST).strftime("%Y%m%d")
    else:
        date = ""


    return dict(
        display_name=display_name,
        from_addr=from_addr,
        dkim_verify=dkim_verify,
        dkim_d=dkim_d,
        date=date,
        subject=subject,
        to=to
    )


def main():
    dir = sys.argv[1]
    for root, dirs, files in os.walk(dir):
        for f in files:
            eml = os.path.join(root, f)
            r = get_info(eml)
            if "qualitia" in r["from_addr"]:
                continue

            if ".ss.jp" in r["from_addr"]:
                continue

            if "qualitia" in r["to"]:
                continue

            print(r)

if __name__ == "__main__":
    main()
