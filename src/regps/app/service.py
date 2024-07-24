from .tasks import check_login, check_upload, upload, verify_vlei, verify_cig
import falcon
from falcon import media
from falcon.http_status import HTTPStatus
import json
from keri.end import ending
import logging
import os
from swagger_ui import api_doc
import sys
from falcon_swagger_ui import register_swaggerui_app

ROUTE_PING = "/ping"
ROUTE_LOGIN = "/login"
ROUTE_CHECK_LOGIN = "/checklogin"
ROUTE_UPLOAD = "/upload"
ROUTE_CHECK_UPLOAD = "/checkupload"
ROUTE_STATUS = "/status"

uploadStatus = {}

# Create a logger object.
logger = logging.getLogger(__name__)

# Configure the logger to write messages to stdout.
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)

# Set the log level to include all messages.
logger.setLevel(logging.DEBUG)


def copyResponse(actual: falcon.Response, copyme: falcon.Response):
    if hasattr(copyme, 'status_code') and hasattr(copyme, 'reason'):
        actual.status = str(copyme.status_code) + " " + copyme.reason
    elif hasattr(copyme, 'status'):
        actual.status = copyme.status
    else:
        logger.error('copyme has neither status_code nor status attribute')

    if hasattr(copyme, 'json'):
        actual.data = json.dumps(copyme.json()).encode("utf-8")
    elif hasattr(copyme, 'data'):
        actual.data = copyme.data
    else:
        logger.error('copyme does not have json attribute')

    if hasattr(copyme, 'headers') and "Content-Type" in copyme.headers:
        actual.content_type = copyme.headers["Content-Type"]
    elif hasattr(copyme, 'content_type'):
        actual.content_type = copyme.content_type
    else:
        logger.error('copyme does not have headers attribute or Content-Type header')


def initStatusDb(aid):
    if aid not in uploadStatus:
        logger.info("Initialized status db for {}".format(aid))
        uploadStatus[aid] = []
    else:
        logger.info("Status db already initialized for {}".format(aid))
    return


# the signature is a keri cigar objects
class VerifySignedHeaders:
    DefaultFields = ["Signify-Resource", "@method", "@path", "Signify-Timestamp"]

    def process_request(self, req: falcon.Request, resp: falcon.Response, raid):
        logger.info(f"Processing signed header verification request {req}")
        aid, cig, ser = self.handle_headers(req)
        if (aid == raid):
            res = verify_cig(aid, cig, ser)
            logger.info(f"VerifySignedHeaders.on_post: response {res}")

            if res.status_code <= 400:
                initStatusDb(aid)
            return res
        else:
            resp.status = falcon.HTTP_401
            resp.data = json.dumps(dict(msg=f"Header AID {aid} does not match request {raid}")).encode("utf-8")
            return resp

    def handle_headers(self, req):
        logger.info(f"processing header req {req}")

        headers = req.headers
        if "SIGNATURE-INPUT" not in headers or "SIGNATURE" not in headers or "SIGNIFY-RESOURCE" not in headers or "SIGNIFY-TIMESTAMP" not in headers:
            return False

        siginput = headers["SIGNATURE-INPUT"]
        if not siginput:
            return False
        signature = headers["SIGNATURE"]
        if not signature:
            return False
        resource = headers["SIGNIFY-RESOURCE"]
        if not resource:
            return False
        timestamp = headers["SIGNIFY-TIMESTAMP"]
        if not timestamp:
            return False

        inputs = ending.desiginput(siginput.encode("utf-8"))
        inputs = [i for i in inputs if i.name == "signify"]

        if not inputs:
            return False

        for inputage in inputs:
            items = []
            for field in inputage.fields:
                if field.startswith("@"):
                    if field == "@method":
                        items.append(f'"{field}": {req.method}')
                    elif field == "@path":
                        items.append(f'"{field}": {req.path}')

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


class LoginTask:

    # Expects a JSON object with the following fields:
    # - said: the SAID of the credential
    # - vlei: the vLEI ECR CESR
    def on_post(self, req: falcon.Request, resp: falcon.Response):
        logger.info("LoginTask.on_post")
        try:
            if req.content_type not in ("application/json",):
                resp.status = falcon.HTTP_BAD_REQUEST
                resp.data = json.dumps(
                    dict(msg=f"invalid content type={req.content_type} for VC presentation, should be application/json",
                         exception_type=type(e).__name__,
                         exception_message=str(e)
                         )).encode("utf-8")
                return

            data = req.media
            if data.get("said") is None:
                resp.status = falcon.HTTP_BAD_REQUEST
                resp.data = json.dumps(
                    dict(msg=f"requests with a said is required",
                         exception_type=type(e).__name__,
                         exception_message=str(e)
                         )).encode("utf-8")
                return
            if data.get("vlei") is None:
                resp.status = falcon.HTTP_BAD_REQUEST
                resp.data = json.dumps(
                    dict(msg=f"requests with vlei ecr cesr is required",
                         exception_type=type(e).__name__,
                         exception_message=str(e)
                         )).encode("utf-8")
                return

            logger.info(f"LoginTask.on_post: sending login cred {str(data)[:50]}...")

            copyResponse(resp, verify_vlei(data["said"], data["vlei"]))

            logger.info(f"LoginTask.on_post: received data {resp.status}")
            return
        except Exception as e:
            logger.info(f"LoginTask.on_post: Exception: {e}")
            resp.status = falcon.HTTP_500
            resp.data = json.dumps(
                dict(msg="Login request failed",
                     exception_type=type(e).__name__,
                     exception_message=str(e)
                     )).encode("utf-8")
            return

    def on_get(self, req: falcon.Request, resp: falcon.Response, aid):
        logger.info("LoginTask.on_get")
        try:
            logger.info(f"LoginTask.on_get: sending aid {aid}")
            copyResponse(resp, check_login(aid))
            logger.info(f"LoginTask.on_get: response {json.dumps(resp.data.decode('utf-8'))}")
            return
        except Exception as e:
            logger.info(f"LoginTask.on_get: Exception: {e}")
            resp.status = falcon.HTTP_500
            resp.data = json.dumps(
                dict(msg="Login check request failed",
                     exception_type=type(e).__name__,
                     exception_message=str(e)
                     )).encode("utf-8")
            return


class UploadTask:

    def __init__(self, verCig: VerifySignedHeaders) -> None:
        self.verCig = verCig

    def on_post(self, req: falcon.Request, resp: falcon.Response, aid, dig):
        logger.info("UploadTask.on_post {}".format(req))
        try:
            check_headers = self.verCig.process_request(req, resp, aid)
            if check_headers.status_code >= 400:
                logger.info(f"UploadTask.on_post: Invalid signature on headers or error was received")
                return copyResponse(resp, check_headers)

            raw = req.bounded_stream.read()
            logger.info(
                f"UploadTask.on_post: request for {aid} {dig} {raw} {req.content_type}"
            )
            upload_resp = upload(aid, dig, req.content_type, raw)

            if upload_resp.status_code >= 400:
                logger.info(f"UploadTask.on_post: Invalid signature on report or error was received")
            else:
                logger.info(f"UploadTask.on_post: completed upload for {aid} {dig} with code {upload_resp.status_code}")

            uploadStatus[f"{aid}"].append(upload_resp.json())
            copyResponse(resp, upload_resp)

            return

        except Exception as e:
            logger.info(f"Upload.on_post: Exception: {e}")
            resp.status = falcon.HTTP_500
            resp.data = json.dumps(
                [dict(submitter=f"{aid}", filename="", status="", contentType="", size=0, message=str(e))]).encode(
                "utf-8")
            return

    def on_get(self, req: falcon.Request, resp: falcon.Response, aid, dig):
        logger.info("UploadTask.on_get")
        copyResponse(resp, self.verCig.process_request(req, resp, aid))
        if resp:
            logger.info(f"UploadTask.on_post: Invalid signature on headers")
            return resp
        try:
            logger.info(f"UploadTask.on_get: sending aid {aid} for dig {dig}")
            curesp = check_upload(aid, dig)
            copyResponse(resp, curesp)
            logger.info(f"UploadTask.on_get: received data {json.dumps(resp.data)}")
            return
        except Exception as e:
            logger.info(f"UploadTask.on_get: Exception: {e}")
            resp.status = falcon.HTTP_500
            resp.data = json.dumps(
                [dict(submitter=f"{aid}", filename="", status="", contentType="", size=0, message=str(e))]).encode(
                "utf-8")
            return


class StatusTask:

    def __init__(self, verCig: VerifySignedHeaders) -> None:
        self.verCig = verCig

    def on_get(self, req: falcon.Request, resp: falcon.Response, aid):
        logger.info(f"StatusTask.on_get request {req}")
        try:
            check_headers = self.verCig.process_request(req, resp, aid)
            if check_headers.status_code >= 400:
                logger.info(f"StatusTask.on_get: Invalid signature on headers or error was received")
                return copyResponse(resp, check_headers)

            logger.info(f"StatusTask.on_get: aid {aid}")
            if aid not in uploadStatus:
                logger.info(f"StatusTask.on_post: Cannot find status for {aid}")
                resp.data = json.dumps(dict(msg=f"AID not logged in: {aid}")).encode("utf-8")
                resp.status = falcon.HTTP_401
                return resp
            else:
                responses = uploadStatus[f"{aid}"]
                if len(responses) == 0:
                    logger.info(f"StatusTask.on_get: Empty upload status list for aid {aid}")
                    resp.status = falcon.HTTP_200
                    resp.data = json.dumps([dict(submitter=f"{aid}", filename="", status="", contentType="", size=0,
                                                 message="No Reports Uploaded")]).encode("utf-8")
                    return resp
                else:
                    logger.info(f"StatusTask.on_get: received data {json.dumps(resp.data)}")
                    resp.status = falcon.HTTP_200
                    resp.data = json.dumps(responses).encode("utf-8")
                    return resp
        except Exception as e:
            logger.info(f"Status.on_get: Exception: {e}")
            resp.status = falcon.HTTP_500
            resp.data = json.dumps(
                [dict(submitter=f"{aid}", filename="", status="", contentType="", size=0, message=str(e))]).encode(
                "utf-8")
            return resp


class HandleCORS(object):
    def process_request(self, req: falcon.Request, resp: falcon.Response):
        resp.set_header("Access-Control-Allow-Origin", "*")
        resp.set_header("Access-Control-Allow-Methods", "*")
        resp.set_header("Access-Control-Allow-Headers", "*")
        resp.set_header("Access-Control-Max-Age", 1728000)  # 20 days
        if req.method == "OPTIONS":
            raise HTTPStatus(falcon.HTTP_200, text="\n")
            return


class PingResource:
    def on_get(self, req: falcon.Request, resp: falcon.Response):
        """Handles GET requests"""
        resp.status = falcon.HTTP_200
        resp.content_type = falcon.MEDIA_TEXT
        resp.text = "Pong"
        return


# class PingSecureResource:

#     def __init__(self, verCig: VerifySignedHeaders) -> None:
#         self.verCig = verCig

#     def on_get(self, req: falcon.Request, resp: falcon.Response, aid):
#         sig_check = self.verCig.process_request(req: falcon.Request, resp: falcon.Response)
#         if sig_check:
#             logger.info(f"SecurePing.on_get: Invalid signature on headers")
#             return sig_check
#         try:
#             logger.info(f"SecurePing.on_get: aid {aid}")
#             """Handles GET requests with headers"""
#             resp.status = falcon.HTTP_200
#             resp.content_type = falcon.MEDIA_TEXT
#             resp.text = "Secure Pong"
#         except Exception as e:
#             logger.info(f"SecurePing.on_get: Exception: {e}")
#             resp.text = f"Exception: {e}"
#             resp.status = falcon.HTTP_500


def getRequiredParam(body, name):
    param = body.get(name)
    if param is None:
        raise falcon.HTTPBadRequest(
            description=f"required field '{name}' missing from request"
        )

    return param


def register_swagger_ui(app):
    vlei_contents = None
    with open("./data/credential.cesr", "r") as cfile:
        vlei_contents = cfile.read()

    # Register Swagger UI
    swagger_ui_url = '/api/doc'  # URL to access Swagger UI
    swagger_json_url = '/api/doc/swagger.json'  # URL to access Swagger JSON

    register_swaggerui_app(
        app,
        swagger_ui_url,
        swagger_json_url,
        page_title="API doc",
        config={
            "docExpansion": "list",
            'app_name': "Regulator portal service api"
        }
    )
    with open('./src/swagger.json', 'r') as f:
        template_str = f.read() % vlei_contents.replace("\"", "'")
        swagger_spec_template = json.loads(template_str)

    class SwaggerSpecResource:
        def on_get(self, req, resp):
            # Copy the template to modify
            swagger_spec = swagger_spec_template.copy()

            # Set the server URL dynamically
            swagger_spec['servers'] = [
                {
                    "url": f"{req.scheme}://{req.host}:{req.port}",
                    "description": "API server"
                }
            ]

            resp.media = swagger_spec

    app.add_route(swagger_json_url, SwaggerSpecResource())


def falcon_app():
    app = falcon.App(
        middleware=falcon.CORSMiddleware(
            allow_origins="*",
            allow_credentials="*",
            expose_headers=[
                "cesr-attachment",
                "cesr-date",
                "content-type",
                "signature",
                "signature-input",
                "signify-resource",
                "signify-timestamp",
            ],
        )
    )
    if os.getenv("ENABLE_CORS", "false").lower() in ("true", "1"):
        logger.info("CORS  enabled")
        app.add_middleware(middleware=HandleCORS())
    app.req_options.media_handlers.update(media.Handlers())
    app.resp_options.media_handlers.update(media.Handlers())

    # the signature is a keri cigar objects
    verCig = VerifySignedHeaders()

    app.add_route(ROUTE_PING, PingResource())
    app.add_route(ROUTE_LOGIN, LoginTask())
    app.add_route(f"{ROUTE_CHECK_LOGIN}" + "/{aid}", LoginTask())
    app.add_route(f"{ROUTE_UPLOAD}" + "/{aid}/{dig}", UploadTask(verCig))
    app.add_route(f"{ROUTE_CHECK_UPLOAD}" + "/{aid}/{dig}", UploadTask(verCig))
    app.add_route(f"{ROUTE_STATUS}" + "/{aid}", StatusTask(verCig))

    register_swagger_ui(app)
    return app


app = falcon_app()


def main():
    logger.info("Starting RegPS...")
    return app


if __name__ == "__main__":
    main()
