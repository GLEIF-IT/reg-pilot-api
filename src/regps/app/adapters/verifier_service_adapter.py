import os
from time import sleep
import json
import logging
import os
import requests
import sys

# Create a logger object.
logger = logging.getLogger(__name__)

# Configure the logger to write messages to stdout.
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)

# Set the log level to include all messages.
logger.setLevel(logging.DEBUG)


class VerifierServiceAdapter:
    def __init__(self):
        # TODO: take only base url for the verifier service from the environment variable
        self.auths_url = os.environ.get('VERIFIER_AUTHORIZATIONS', "http://127.0.0.1:7676/authorizations/")
        self.presentations_url = os.environ.get('VERIFIER_PRESENTATIONS', "http://127.0.0.1:7676/presentations/")
        self.reports_url = os.environ.get('VERIFIER_REPORTS', "http://127.0.0.1:7676/reports/")
        self.request_url = os.environ.get('VERIFIER_REQUESTS', "http://localhost:7676/request/verify/")

    def check_login_request(self, aid: str) -> requests.Response:
        logger.info(f"checking login: {aid}")
        logger.info(f"getting from {self.auths_url}{aid}")
        res = requests.get(f"{self.auths_url}{aid}", headers={"Content-Type": "application/json"})
        logger.info(f"login status: {json.dumps(res.json())}")
        return res

    def verify_vlei_request(self, said: str, vlei: str) -> requests.Response:
        logger.info(f"Verify vlei task started {said} {vlei[:50]}")
        logger.info(f"presenting vlei ecr to url {self.presentations_url}{said}")
        res = requests.put(f"{self.presentations_url}{said}", headers={"Content-Type": "application/json+cesr"},
                           data=vlei)
        logger.info(f"verify vlei task response {json.dumps(res.json())}")
        return res

    def verify_cig_request(self, aid, cig, ser) -> requests.Response:
        logger.info("Verify header sig started aid = {}, cig = {}, ser = {}....".format(aid, cig, ser))
        logger.info("posting to {}".format(self.request_url + f"{aid}"))
        res = requests.post(self.request_url + aid, params={"sig": cig, "data": ser})
        logger.info(f"Verify sig response {json.dumps(res.json())}")
        return res

    def check_upload_request(self, aid: str, dig: str) -> requests.Response:
        logger.info(f"checking upload: aid {aid} and dig {dig}")
        logger.info(f"getting from {self.reports_url}{aid}/{dig}")
        res = requests.get(f"{self.reports_url}{aid}/{dig}", headers={"Content-Type": "application/json"})
        logger.info(f"upload status: {json.dumps(res.json())}")
        return res

    def upload_request(self, aid: str, dig: str, contype: str, report) -> requests.Response:
        logger.info(f"upload report type {type(report)}")
        # first check to see if we've already uploaded
        cres = self.check_upload_request(aid, dig)
        if cres.status_code == 200:
            logger.info(f"upload already uploaded: {json.dumps(cres.json())}")
            return cres
        else:
            logger.info(f"upload posting to {self.reports_url}{aid}/{dig}")
            cres = requests.post(f"{self.reports_url}{aid}/{dig}", headers={"Content-Type": contype}, data=report)
            logger.info(f"post response {json.dumps(cres.json())}")
            if cres.status_code < 300:
                cres = self.check_upload_request(aid, dig)
                if cres.status_code != 200:
                    logger.info(f"Checking upload status.... {json.dumps(cres.json())}")
                    for i in range(10):
                        if cres is None or cres.status_code == 404:
                            cres = self.check_upload_request(aid, dig)
                            print(f"polling result for {aid} and {dig}: {cres.text}")
                            sleep(1)
                            i += 1
                        else:
                            break
        logger.info(f"Checked upload result: {json.dumps(cres.json())}")
        return cres
