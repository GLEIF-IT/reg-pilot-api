import os
from regps.app.api.signed_headers_verifier import logger, VerifySignedHeaders
from fastapi import (
    FastAPI,
    Header,
    HTTPException,
    Request,
    Path,
    Response,
)
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from regps.app.api.utils.pydantic_models import (
    LoginRequest,
    LoginResponse,
    CheckLoginResponse,
    UploadResponse,
)
from regps.app.api.exceptions import (
    VerifierServiceException,
)
from regps.app.api.controllers import APIController
from regps.app.api.utils.reports_db import ReportsDB
from regps.app.api.utils.swagger_examples import (
    check_login_examples,
    upload_examples,
    check_upload_examples,
)

app = FastAPI(
    title="Regulator portal service api",
    description="Regulator web portal service api",
    version="1.0.0",
)

api_controller = APIController()
verify_signed_headers = VerifySignedHeaders(api_controller)
reports_db = ReportsDB()

@app.get("/ping")
async def ping():
    """
    Health check endpoint.
    """
    return "Pong"


@app.post("/login", response_model=LoginResponse)
async def login(response: Response, data: LoginRequest):
    """
    Given an AID and vLEI, returns information about the login
    """
    try:
        logger.info(f"Login: sending login cred {str(data)[:50]}...")
        resp = api_controller.login(data.said, data.vlei)
        lei = resp.get("lei")
        aid = resp.get("aid")
        reports_db.register_aid(aid, lei)
        return JSONResponse(status_code=202, content=resp)
    except VerifierServiceException as e:
        logger.error(f"Login: Exception: {e}")
        response.status_code = e.status_code
        return JSONResponse(content=e.detail, status_code=e.status_code)
    except Exception as e:
        logger.error(f"Login: Exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/checklogin/{aid}", response_model=CheckLoginResponse)
async def check_login_route(
    response: Response,
    aid: str = Path(
        ...,
        description="AID",
        openapi_examples={
            "default": {
                "summary": "Default AID",
                "value": check_login_examples["request"]["aid"],
            }
        },
    ),
):
    """
    Given an AID returns information about the login
    """
    try:
        logger.info(f"CheckLogin: sending aid {aid}")
        resp = api_controller.check_login(aid)
        return JSONResponse(status_code=200, content=resp)
    except VerifierServiceException as e:
        logger.error(f"CheckLogin: Exception: {e}")
        response.status_code = e.status_code
        return JSONResponse(content=e.detail, status_code=e.status_code)
    except Exception as e:
        logger.error(f"CheckLogin: Exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# TODO: Add upload form-data param to the required parameters and add it to the DOC
@app.post("/upload/{aid}/{dig}", response_model=UploadResponse)
async def upload_route(
    request: Request,
    response: Response,
    aid: str = Path(
        ...,
        description="AID",
        openapi_examples={
            "default": {
                "summary": "Default AID",
                "value": upload_examples["request"]["aid"],
            }
        },
    ),
    dig: str = Path(
        ...,
        description="DIG",
        openapi_examples={
            "default": {
                "summary": "Default AID",
                "value": upload_examples["request"]["dig"],
            }
        },
    ),
    signature: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signature",
                "value": upload_examples["request"]["headers"]["signature"],
            }
        }
    ),
    signature_input: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signature_input",
                "value": upload_examples["request"]["headers"]["signature_input"],
            }
        }
    ),
    signify_resource: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signify_resource",
                "value": upload_examples["request"]["headers"]["signify_resource"],
            }
        }
    ),
    signify_timestamp: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signify_timestamp",
                "value": upload_examples["request"]["headers"]["signify_timestamp"],
            }
        }
    ),
):
    """
    Given an AID and DIG, returns information about the upload
    """
    try:
        verify_signed_headers.process_request(request, aid)
        raw = await request.body()
        form = await request.form()
        upload = form.get("upload")
        report = await upload.read()
        logger.info(
            f"Upload: request for {aid} {dig} {raw} {request.headers.get('Content-Type')}"
        )
        resp = api_controller.upload(
            aid, dig, report, request.headers.get("Content-Type"), raw
        )

        if resp.status_code >= 400:
            logger.info("Upload: Invalid signature on report or error was received")
        else:
            logger.info(
                f"Upload: completed upload for {aid} {dig} with code {resp.status_code}"
            )
        reports_db.add_report(aid, dig, resp.json())
        return JSONResponse(status_code=200, content=resp.json())
    except HTTPException as e:
        logger.error(f"Upload: Exception: {e}")
        response.status_code = e.status_code
        return JSONResponse(content=e.detail, status_code=e.status_code)
    except Exception as e:
        logger.error(f"Upload: Unknown Exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/upload/{aid}/{dig}")
async def check_upload_route(
    request: Request,
    response: Response,
    aid: str = Path(
        ...,
        description="AID",
        openapi_examples={
            "default": {
                "summary": "Default AID",
                "value": check_upload_examples["request"]["aid"],
            }
        },
    ),
    dig: str = Path(
        ...,
        description="DIG",
        openapi_examples={
            "default": {
                "summary": "The file digest",
                "value": check_upload_examples["request"]["dig"],
            }
        },
    ),
    signature: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signature",
                "value": upload_examples["request"]["headers"]["signature"],
            }
        }
    ),
    signature_input: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signature_input",
                "value": upload_examples["request"]["headers"]["signature_input"],
            }
        }
    ),
    signify_resource: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signify_resource",
                "value": upload_examples["request"]["headers"]["signify_resource"],
            }
        }
    ),
    signify_timestamp: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signify_timestamp",
                "value": upload_examples["request"]["headers"]["signify_timestamp"],
            }
        }
    ),
):
    """
    Check upload status by aid and dig.
    """
    try:
        verify_signed_headers.process_request(request, aid)
        if not reports_db.authorized_to_check_status(aid, dig):
            raise HTTPException(status_code=401, detail=f"AID {aid} is not authorized to check status for digest {dig}")
        resp = api_controller.check_upload(aid, dig)
        return JSONResponse(status_code=200, content=resp)
    except VerifierServiceException as e:
        logger.error(f"CheckUpload: Exception: {e}")
        response.status_code = e.status_code
        return JSONResponse(content=e.detail, status_code=e.status_code)
    except HTTPException as e:
        logger.error(f"CheckUpload: Exception: {e}")
        response.status_code = e.status_code
        return JSONResponse(content=e.detail, status_code=e.status_code)
    except Exception as e:
        logger.error(f"CheckUpload: Exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/status/{aid}")
async def status_route(
    request: Request,
    response: Response,
    aid: str = Path(
        ...,
        description="AID",
        openapi_examples={
            "default": {
                "summary": "Default AID",
                "value": check_upload_examples["request"]["aid"],
            }
        },
    ),
    signature: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signature",
                "value": upload_examples["request"]["headers"]["signature"],
            }
        }
    ),
    signature_input: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signature_input",
                "value": upload_examples["request"]["headers"]["signature_input"],
            }
        }
    ),
    signify_resource: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signify_resource",
                "value": upload_examples["request"]["headers"]["signify_resource"],
            }
        }
    ),
    signify_timestamp: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signify_timestamp",
                "value": upload_examples["request"]["headers"]["signify_timestamp"],
            }
        }
    ),
):
    """
    Check upload status by aid.
    """
    try:
        verify_signed_headers.process_request(request, aid)
        resp = reports_db.get_reports_for_aid(aid)
        return JSONResponse(status_code=202, content=resp)
    except HTTPException as e:
        logger.error(f"Status: Exception: {e}")
        response.status_code = e.status_code
        return JSONResponse(content=e.detail, status_code=e.status_code)
    except Exception as e:
        logger.error(f"Status: Exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/report/status/lei/{aid}")
async def status_for_lei_route(
    request: Request,
    response: Response,
    aid: str = Path(
        ...,
        description="AID",
        openapi_examples={
            "default": {
                "summary": "Default AID",
                "value": check_upload_examples["request"]["aid"],
            }
        },
    ),
    signature: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signature",
                "value": upload_examples["request"]["headers"]["signature"],
            }
        }
    ),
    signature_input: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signature_input",
                "value": upload_examples["request"]["headers"]["signature_input"],
            }
        }
    ),
    signify_resource: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signify_resource for signed headers.",
                "value": upload_examples["request"]["headers"]["signify_resource"],
            }
        }
    ),
    signify_timestamp: str = Header(
        openapi_examples={
            "default": {
                "summary": "Default signify_timestamp for signed headers.",
                "value": upload_examples["request"]["headers"]["signify_timestamp"],
            }
        }
    ),
):
    """
    Check upload status by aid.
    """
    try:
        verify_signed_headers.process_request(request, aid)
        resp = reports_db.get_reports_for_lei(aid)
        return JSONResponse(status_code=202, content=resp)
    except VerifierServiceException as e:
        logger.error(f"Status: Exception: {e}")
        response.status_code = e.status_code
        return JSONResponse(content=e.detail, status_code=e.status_code)
    except Exception as e:
        logger.error(f"Status: Exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# TODO: Remove this endpoint when we will have DB. IT's only for tests
@app.post("/status/{aid}/drop")
def clear_status_route(
    request: Request,
    aid: str = Path(
        ...,
        description="AID",
        openapi_examples={
            "default": {
                "summary": "Default AID",
                "value": check_upload_examples["request"]["aid"],
            }
        },
    ),
):
    """
    Drop upload status for specified AID. For the test purposes
    """
    verify_signed_headers.process_request(request, aid)
    reports_db.drop_status(aid)
    resp = {"status": "success", "aid": aid}
    return JSONResponse(status_code=202, content=resp)


if os.getenv("ENABLE_CORS", "true").lower() in ("true", "1"):
    logger.info("CORS enabled")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
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


def main():
    logger.info("Starting RegPS...")
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
