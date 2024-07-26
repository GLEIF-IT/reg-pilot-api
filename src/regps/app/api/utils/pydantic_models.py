from fastapi import Path
from pydantic import BaseModel, Field
from regps.app.api.utils.swagger_examples import login_examples, check_login_examples, upload_examples


class LoginRequest(BaseModel):
    said: str = Field(examples=login_examples["request"]["said"])
    vlei: str = Field(examples=login_examples["request"]["vlei"])


class LoginResponse(BaseModel):
    aid: str = Field(examples=login_examples["response"]["aid"])
    said: str = Field(examples=login_examples["response"]["said"])


class CheckLoginResponse(BaseModel):
    aid: str = Field(examples=check_login_examples["response"]["aid"])
    said: str = Field(examples=check_login_examples["response"]["said"])


class UploadResponse(BaseModel):
    submitter: str = Field(examples=upload_examples["response"]["submitter"])
    filename: str = Field(examples=upload_examples["response"]["filename"])
    status: str = Field(examples=upload_examples["response"]["status"])
    contentType: str = Field(examples=upload_examples["response"]["contentType"])
    size: int = Field(examples=upload_examples["response"]["size"])
    message: str = Field(examples=upload_examples["response"]["message"])


class CheckUploadResponse(BaseModel):
    pass
