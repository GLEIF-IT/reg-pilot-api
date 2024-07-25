import json
from typing import Any, Dict, List
import logging
from regps.app.api.exceptions import VerifySignedHeadersException
import sys
from fastapi import Request
from keri.end import ending

# Configure the logger
logger = logging.getLogger(__name__)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

uploadStatus: Dict[str, List[Dict[str, Any]]] = {}


class VerifySignedHeaders:
    DefaultFields = ["Signify-Resource", "@method", "@path", "Signify-Timestamp"]

    def __init__(self, api_controller):
        self.api_controller = api_controller

    def process_request(self, req: Request, raid):
        try:
            logger.info(f"Processing signed header verification request {req}")
            aid, cig, ser = self.handle_headers(req)
            if aid == raid:
                res = self.api_controller.verify_cig(aid, cig, ser)
                logger.info(f"VerifySignedHeaders.on_post: response {res}")
                return res
            else:
                raise VerifySignedHeadersException(
                    json.dumps({"msg": f"Header AID {aid} does not match request {raid}"}), 401)
        except VerifySignedHeadersException as e:
            raise e

    @staticmethod
    def handle_headers(req):
        logger.info(f"processing header req {req}")

        headers = req.headers
        if "SIGNATURE-INPUT" not in headers or "SIGNATURE" not in headers or "SIGNIFY-RESOURCE" not in headers or "SIGNIFY-TIMESTAMP" not in headers:
            raise VerifySignedHeadersException(json.dumps({"msg": f"Incorrect Headers"}), 401)

        siginput = headers["SIGNATURE-INPUT"]
        signature = headers["SIGNATURE"]
        resource = headers["SIGNIFY-RESOURCE"]
        timestamp = headers["SIGNIFY-TIMESTAMP"]

        inputs = ending.desiginput(siginput.encode("utf-8"))
        inputs = [i for i in inputs if i.name == "signify"]

        if not inputs:
            raise VerifySignedHeadersException(json.dumps({"msg": f"Incorrect Headers"}), 401)

        for inputage in inputs:
            items = []
            for field in inputage.fields:
                if field.startswith("@"):
                    if field == "@method":
                        items.append(f'"{field}": {req.method}')
                    elif field == "@path":
                        items.append(f'"{field}": {req.url.path}')

                else:
                    key = field.upper()
                    field = field.lower()
                    if key not in headers:
                        continue

                    value = ending.normalize(headers[key])
                    items.append(f'"{field}": {value}')

            values = [f"({' '.join(inputage.fields)})", f"created={inputage.created}"]
            if inputage.expires is not None:
                values.append(f"expires={inputage.expires}")
            if inputage.nonce is not None:
                values.append(f"nonce={inputage.nonce}")
            if inputage.keyid is not None:
                values.append(f"keyid={inputage.keyid}")
            if inputage.context is not None:
                values.append(f"context={inputage.context}")
            if inputage.alg is not None:
                values.append(f"alg={inputage.alg}")

            params = ";".join(values)

            items.append(f'"@signature-params: {params}"')
            ser = "\n".join(items)

            signages = ending.designature(signature)
            cig = signages[0].markers[inputage.name]
            assert len(signages) == 1
            assert signages[0].indexed is False
            assert "signify" in signages[0].markers

            aid = resource
            sig = cig.qb64
            logger.info(f"verification input aid={aid} ser={ser} cig={sig}")
            return aid, sig, ser
