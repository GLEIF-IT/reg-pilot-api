from time import sleep
import falcon
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

auths_url = "http://127.0.0.1:7676/authorizations/"
presentations_url = "http://127.0.0.1:7676/presentations/"
reports_url = "http://127.0.0.1:7676/reports/"
request_url = "http://localhost:7676/request/verify/"

VERIFIER_AUTHORIZATIONS = os.environ.get('VERIFIER_AUTHORIZATIONS')
if VERIFIER_AUTHORIZATIONS is None:
        logger.info(f"VERIFIER_AUTHORIZATIONS is not set. Using default {auths_url}")
else:
        logger.info(f"VERIFIER_AUTHORIZATIONS is set. Using {VERIFIER_AUTHORIZATIONS}")
        auths_url = VERIFIER_AUTHORIZATIONS
        
VERIFIER_PRESENTATIONS = os.environ.get('VERIFIER_PRESENTATIONS')
if VERIFIER_PRESENTATIONS is None:
        logger.info(f"VERIFIER_PRESENTATIONS is not set. Using default {presentations_url}")
else:
        logger.info(f"VERIFIER_PRESENTATIONS is set. Using {VERIFIER_PRESENTATIONS}")
        presentations_url = VERIFIER_PRESENTATIONS

VERIFIER_REPORTS = os.environ.get('VERIFIER_REPORTS')
if VERIFIER_REPORTS is None:
        logger.info(f"VERIFIER_REPORTS is not set. Using default {reports_url}")
else:
        logger.info(f"VERIFIER_REPORTS is set. Using {VERIFIER_REPORTS}")
        reports_url = VERIFIER_REPORTS
        
VERIFIER_REQUESTS = os.environ.get('VERIFIER_REQUESTS')
if VERIFIER_REQUESTS is None:
        logger.info(f"VERIFIER_REQUESTS is not set. Using default {request_url}")
else:
        logger.info(f"VERIFIER_REQUESTS is set. Using {VERIFIER_REQUESTS}")
        request_url = VERIFIER_REQUESTS

def check_login(aid: str) -> falcon.Response:
    logger.info(f"checking login: {aid}")
    logger.info(f"getting from {auths_url}{aid}")
    res = requests.get(f"{auths_url}{aid}", headers={"Content-Type": "application/json"})
    logger.info(f"login status: {json.dumps(res.json())}")
    return res

def verify_vlei(said: str, vlei: str) -> falcon.Response:
    logger.info(f"Verify vlei task started {said} {vlei[:50]}")
    logger.info(f"presenting vlei ecr to url {presentations_url}{said}")
    res = requests.put(f"{presentations_url}{said}", headers={"Content-Type": "application/json+cesr"}, data=vlei)
    logger.info(f"verify vlei task response {json.dumps(res.json())}")
    return res
        
def verify_cig(aid,cig,ser) -> falcon.Response:
    logger.info("Verify header sig started aid = {}, cig = {}, ser = {}....".format(aid,cig,ser))
    logger.info("posting to {}".format(request_url+f"{aid}"))
    res = requests.post(request_url+aid, params={"sig": cig,"data": ser})
    logger.info(f"Verify sig response {json.dumps(res.json())}")
    return res

def check_upload(aid: str, dig: str) -> falcon.Response:
    logger.info(f"checking upload: aid {aid} and dig {dig}")
    logger.info(f"getting from {reports_url}{aid}/{dig}")
    res = requests.get(f"{reports_url}{aid}/{dig}", headers={"Content-Type": "application/json"})
    logger.info(f"upload status: {json.dumps(res.json())}")
    return res

def upload(aid: str, dig: str, contype: str, report) -> falcon.Response:
    logger.info(f"upload report type {type(report)}")
    # first check to see if we've already uploaded
    cres = check_upload(aid, dig)
    if cres.status_code == falcon.http_status_to_code(falcon.HTTP_OK):
        logger.info(f"upload already uploaded: {json.dumps(cres.json())}")
        return cres
    else:
        logger.info(f"upload posting to {reports_url}{aid}/{dig}")
        cres = requests.post(f"{reports_url}{aid}/{dig}", headers={"Content-Type": contype}, data=report)
        logger.info(f"post response {json.dumps(cres.json())}")
        if cres.status_code < falcon.http_status_to_code(falcon.HTTP_300):
            cres = check_upload(aid, dig)
            if cres.status_code != falcon.http_status_to_code(falcon.HTTP_OK):
                logger.info(f"Checking upload status.... {json.dumps(cres.json())}")
                for i in range(10):
                    if cres == None or cres.status_code == falcon.http_status_to_code(falcon.HTTP_404):
                        cres = check_upload(aid, dig)
                        print(f"polling result for {aid} and {dig}: {cres.text}")
                        sleep (1)
                        i += 1
                    else:
                        break
    logger.info(f"Checked upload result: {json.dumps(cres.json())}")
    return cres