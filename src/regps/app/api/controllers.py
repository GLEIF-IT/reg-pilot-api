import requests
from regps.app.adapters.verifier_service_adapter import VerifierServiceAdapter
from regps.app.api.exceptions import (
    VerifierServiceException,
    DigestVerificationFailedException,
)
from regps.app.api.digest_verifier import verify_digest


class APIController:
    def __init__(self):
        self.verifier_adapter = VerifierServiceAdapter()

    def check_login(self, aid: str):
        verifier_response: requests.Response = (
            self.verifier_adapter.check_login_request(aid)
        )
        if verifier_response.status_code != 200:
            raise VerifierServiceException(
                verifier_response.json(), verifier_response.status_code
            )
        return verifier_response.json()

    def login(self, said: str, vlei: str):
        verifier_response = self.verifier_adapter.verify_vlei_request(said, vlei)
        if verifier_response.status_code != 202:
            raise VerifierServiceException(
                verifier_response.json(), verifier_response.status_code
            )
        return verifier_response.json()

    def verify_cig(self, aid, cig, ser):
        verifier_response = self.verifier_adapter.verify_cig_request(aid, cig, ser)
        if verifier_response.status_code != 202:
            raise VerifierServiceException(
                verifier_response.json(), verifier_response.status_code
            )
        return verifier_response.json()

    def check_upload(self, aid: str, dig: str):
        verifier_response = self.verifier_adapter.check_upload_request(aid, dig)
        if verifier_response.status_code != 200:
            raise VerifierServiceException(
                verifier_response.json(), verifier_response.status_code
            )
        return verifier_response.json()

    def upload(self, aid: str, dig: str, report: bytes, contype: str, raw):
        if not verify_digest(report, dig):
            raise DigestVerificationFailedException(
                "Report digest verification failed", 400
            )
        verifier_response = self.verifier_adapter.upload_request(aid, dig, contype, raw)
        if verifier_response.status_code != 200:
            raise VerifierServiceException(
                verifier_response.json(), verifier_response.status_code
            )
        return verifier_response
