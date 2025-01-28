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


class FilerServiceAdapter:
    def __init__(self):
        self.reports_url = os.environ.get(
            "FILER_REPORTS", "http://localhost:7878/reports/"
        )
        self.upload_statuses_admin_url = os.environ.get(
            "FILER_ADMIN_UPLOAD_STATUSES", "http://localhost:7878/admin/upload_statuses/"
        )


    def upload_statuses_admin_request(self, aid: str, lei: str="") -> requests.Response:
        logger.info(f"checking upload statuses by Data Admin: aid {aid} and dig {lei}")
        logger.info(f"getting from {self.upload_statuses_admin_url}{aid}/{lei}")
        res = requests.get(
            f"{self.upload_statuses_admin_url}{aid}/{lei}",
            headers={"Content-Type": "application/json"},
        )
        logger.info(f"upload statuses: {json.dumps(res.json())}")
        return res

    def check_upload_request(self, aid: str, dig: str) -> requests.Response:
        logger.info(f"checking upload: aid {aid} and dig {dig}")
        logger.info(f"getting from {self.reports_url}{aid}/{dig}")
        res = requests.get(
            f"{self.reports_url}{aid}/{dig}",
            headers={"Content-Type": "application/json"},
        )
        logger.info(f"upload status: {json.dumps(res.json())}")
        return res

    def upload_request(
        self, aid: str, dig: str, contype: str, report
    ) -> requests.Response:
        logger.info(f"upload report type {type(report)}")
        # first check to see if we've already uploaded
        cres = self.check_upload_request(aid, dig)
        if cres.status_code == 200:
            logger.info(f"upload already uploaded: {json.dumps(cres.json())}")
            return cres
        else:
            logger.info(f"upload posting to {self.reports_url}{aid}/{dig}")
            cres = requests.post(
                f"{self.reports_url}{aid}/{dig}",
                headers={"Content-Type": contype},
                data=report,
            )
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
