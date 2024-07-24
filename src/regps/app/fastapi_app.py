import os

from regps.app.api.signed_headers_verifier import logger, VerifySignedHeaders
from fastapi import FastAPI, Header, HTTPException, Request, File, UploadFile, Path
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from regps.app.api.utils.pydantic_models import LoginRequest, LoginResponse, CheckLoginResponse, CheckUploadResponse, \
    UploadResponse
from regps.app.api.exceptions import VerifierServiceException, VerifySignedHeadersException
from regps.app.api.controllers import APIController
from regps.app.api.utils.swagger_examples import login_examples, check_login_examples, upload_examples, \
    check_upload_examples

app = FastAPI(title="Regulator portal service api", description="Regulator web portal service api")

api_controller = APIController()
verify_signed_headers = VerifySignedHeaders(api_controller)


@app.get("/ping")
async def ping():
    """
    Health check endpoint.
    """
    return "Pong"


@app.post("/login", response_model=LoginResponse)
async def login(data: LoginRequest):
    """
    Given an AID and vLEI, returns information about the login
    """
    try:
        logger.info(f"Login: sending login cred {str(data)[:50]}...")
        response = api_controller.login(data.said, data.vlei)
        return JSONResponse(status_code=200, content=response)
    except VerifierServiceException as e:
        logger.error(f"Login: Exception: {e}")
        raise e
    except Exception as e:
        logger.error(f"Login: Exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/checklogin/{aid}", response_model=CheckLoginResponse)
async def check_login_route(aid: str = Path(example=check_login_examples["request"]["aid"])):
    """
    Given an AID returns information about the login
    """
    try:
        logger.info(f"CheckLogin: sending aid {aid}")
        response = api_controller.check_login(aid)
        return JSONResponse(status_code=200, content=response)
    except VerifierServiceException as e:
        logger.error(f"CheckLogin: Exception: {e}")
        raise e
    except Exception as e:
        logger.error(f"CheckLogin: Exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/upload/{aid}/{dig}", response_model=UploadResponse)
async def upload_route(request: Request, aid: str = Path(example=upload_examples["request"]["aid"]),
                       dig: str = Path(example=upload_examples["request"]["dig"]), upload: UploadFile = File(...),
                       signature: str = Header(example=upload_examples["request"]["headers"]["signature"]),
                       signature_input: str = Header(example=upload_examples["request"]["headers"]["signature_input"]),
                       signify_resource: str = Header(
                           example=upload_examples["request"]["headers"]["signify_resource"]),
                       signify_timestamp: str = Header(
                           example=upload_examples["request"]["headers"]["signify_timestamp"])
                       ):
    """
    Given an AID and DIG, returns information about the upload
    """
    try:
        verify_signed_headers.process_request(request, aid)
        raw = await upload.read()
        logger.info(
            f"Upload: request for {aid} {dig} {raw} {request.headers.get('Content-Type')}"
        )
        response = api_controller.upload(aid, dig, request.headers.get('Content-Type'), raw)

        if response.status_code >= 400:
            logger.info(f"Upload: Invalid signature on report or error was received")
        else:
            logger.info(f"Upload: completed upload for {aid} {dig} with code {response.status_code}")

        return JSONResponse(status_code=200, content=response)
    except VerifierServiceException or VerifySignedHeadersException as e:
        logger.error(f"Upload: Exception: {e}")
        raise e
    except Exception as e:
        logger.error(f"Upload: Exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/checkupload/{aid}/{dig}")
async def check_upload_route(request: Request, aid: str = Path(example=check_upload_examples["request"]["aid"]),
                             dig: str = Path(example=check_upload_examples["request"]["dig"]),
                             signature: str = Header(example=upload_examples["request"]["headers"]["signature"]),
                             signature_input: str = Header(
                                 example=upload_examples["request"]["headers"]["signature_input"]),
                             signify_resource: str = Header(
                                 example=upload_examples["request"]["headers"]["signify_resource"]),
                             signify_timestamp: str = Header(
                                 example=upload_examples["request"]["headers"]["signify_timestamp"])
                             ):
    """
    Check upload status by aid and dig.
    """
    try:
        verify_signed_headers.process_request(request, aid)
        response = api_controller.check_upload(aid, dig)
        return JSONResponse(status_code=200, content=response)
    except VerifierServiceException as e:
        logger.error(f"CheckUpload: Exception: {e}")
        raise e
    except Exception as e:
        logger.error(f"CheckUpload: Exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if os.getenv("ENABLE_CORS", "true").lower() in ("true", "1"):
    logger.info("CORS enabled")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "cesr-attachment", "cesr-date", "content-type", "signature", "signature-input",
            "signify-resource", "signify-timestamp"
        ]
    )


def main():
    logger.info("Starting RegPS...")
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
