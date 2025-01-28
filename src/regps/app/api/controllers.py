import os

from regps.app.adapters.filer_service_adapter import FilerServiceAdapter
from regps.app.api.exceptions import (
    VerifierServiceException,
    DigestVerificationFailedException,
)
from regps.app.api.digest_verifier import verify_digest
from vlei_verifier_client import VerifierClient, VerifierResponse


class APIController:
    def __init__(self):
        verifier_base_url = os.environ.get("VLEI_VERIFIER", "http://localhost:7676")
        self.verifier_client = VerifierClient(verifier_base_url)
        self.filer_adapter = FilerServiceAdapter()

    def check_login(self, aid: str):
        verifier_response: VerifierResponse = self.verifier_client.check_login(aid)
        if verifier_response.code != 200:
            raise VerifierServiceException(
                verifier_response.message, verifier_response.code
            )
        return verifier_response.body

    def login(self, said: str, vlei: str):
        verifier_response: VerifierResponse = self.verifier_client.login(said, vlei)
        if verifier_response.code != 202:
            raise VerifierServiceException(
                verifier_response.message, verifier_response.code
            )
        return verifier_response.body

    def add_root_of_trust(self, aid, vlei, oobi):
        verifier_response: VerifierResponse = self.verifier_client.add_root_of_trust(aid, vlei, oobi)
        if verifier_response.code != 202:
            raise VerifierServiceException(
                verifier_response.message, verifier_response.code
            )
        return verifier_response.body

    def verify_cig(self, aid, cig, ser):
        verifier_response: VerifierResponse = self.verifier_client.verify_signed_headers(aid, cig, ser)
        if verifier_response.code != 202:
            raise VerifierServiceException(
                verifier_response.message, verifier_response.code
            )
        return verifier_response.body

    def check_upload(self, aid: str, dig: str):
        filer_response = self.filer_adapter.check_upload_request(aid, dig)
        if filer_response.status_code != 200:
            raise VerifierServiceException(
                filer_response.json(), filer_response.status_code
            )
        return filer_response.json()

    def get_upload_statuses_admin(self, aid: str, lei: str):
        filer_response = self.filer_adapter.upload_statuses_admin_request(aid, lei)
        if filer_response.status_code != 200:
            raise VerifierServiceException(
                filer_response.json(), filer_response.status_code
            )
        return filer_response.json()

    def upload(self, aid: str, dig: str, report: bytes, contype: str, raw):
        if not verify_digest(report, dig):
            raise DigestVerificationFailedException(
                "Report digest verification failed", 400
            )
        filer_response = self.filer_adapter.upload_request(aid, dig, contype, raw)
        return filer_response
