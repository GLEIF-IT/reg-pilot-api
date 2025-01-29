from fastapi import HTTPException


class VerifierServiceException(HTTPException):
    def __init__(self, detail: any, status_code: int):
        super().__init__(status_code=status_code, detail=detail)


class VerifySignedHeadersException(HTTPException):
    def __init__(self, detail: any, status_code: int):
        super().__init__(status_code=status_code, detail=detail)


class DigestVerificationFailedException(HTTPException):
    def __init__(self, detail: any, status_code: int):
        super().__init__(status_code=status_code, detail=detail)

class PresentRevocationFailedException(HTTPException):
    def __init__(self, detail: any, status_code: int):
        super().__init__(status_code=status_code, detail=detail)
