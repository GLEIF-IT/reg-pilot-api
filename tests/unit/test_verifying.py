import fastapi
from starlette.datastructures import Headers

from regps.app.api.exceptions import DigestVerificationFailedException
from regps.app.api import signed_headers_verifier
import pytest
from hashlib import sha256
from regps.app.api.digest_verifier import verify_digest


def test_digest_verification():
    BASE_STR = "fefUBIUhdo9032bfHf0UNONF0kubni9HnF22L0KD2".encode()
    dig = sha256(BASE_STR).hexdigest()
    dig = f"sha256_{dig}"
    assert verify_digest(BASE_STR, dig) is True


def test_digest_verification_fail():
    BASE_STR = "fefUBIUhdo9032bfHf0UNONF0kubni9HnF22L0KD2".encode()
    WRONG_BASE_STR = "fefUBIUhdo9032bfHf0UNONF0kubni9HnF22L0KDT".encode()
    dig = sha256(BASE_STR).hexdigest()
    dig = f"sha256_{dig}"
    assert verify_digest(WRONG_BASE_STR, dig) is False


def test_digest_verification_wrong_dig():
    BASE_STR = "fefUBIUhdo9032bfHf0UNONF0kubni9HnF22L0KD2".encode()
    dig = sha256(BASE_STR).hexdigest()
    # Here the dig is not prefixed
    with pytest.raises(DigestVerificationFailedException):
        verify_digest(BASE_STR, dig)


def test_verify_cig():
    # AID and SAID should be the same as what is in credential.cesr for the ECR credential
    # see https://trustoverip.github.io/tswg-acdc-specification/#top-level-fields to understand the fields/values
    AID = "EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x"
    # SAID = "EElnd1DKvcDzzh7u7jBjsg2X9WgdQQuhgiu80i2VR-gk"

    headers = {
        "HOST": "localhost:7676",
        "CONNECTION": "keep-alive",
        "METHOD": "POST",
        "SIGNATURE": 'indexed="?0";signify="0BBbeeBw3lVmQWYBpcFH9KmRXZocrqLH_LZL4aqg5W9-NMdXqIYJ-Sao7colSTJOuYllMXFfggoMhkfpTKnvPhUF"',
        "SIGNATURE-INPUT": 'signify=("@method" "@path" "signify-resource" "signify-timestamp");created=1714854033;keyid="BPoZo2b3r--lPBpURvEDyjyDkS65xBEpmpQhHQvrwlBE";alg="ed25519"',
        "SIGNIFY-RESOURCE": "EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x",
        "SIGNIFY-TIMESTAMP": "2024-05-04T20:20:33.730000+00:00",
        "ACCEPT": "*/*",
        "ACCEPT-LANGUAGE": "*",
        "SEC-FETCH-MODE": "cors",
        "USER-AGENT": "node",
        "ACCEPT-ENCODING": "gzip, deflate",
    }
    scope = dict(type="http", headers=Headers(headers).raw, method="POST", path="/")
    req = fastapi.Request(scope)
    aid, sig, ser = signed_headers_verifier.VerifySignedHeaders.handle_headers(req)
    assert aid == AID
    assert (
        sig
        == "0BBbeeBw3lVmQWYBpcFH9KmRXZocrqLH_LZL4aqg5W9-NMdXqIYJ-Sao7colSTJOuYllMXFfggoMhkfpTKnvPhUF"
    )
    assert (
        ser
        == '"@method": POST\n"@path": /\n"signify-resource": EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x\n"signify-timestamp": 2024-05-04T20:20:33.730000+00:00\n"@signature-params: (@method @path signify-resource signify-timestamp);created=1714854033;keyid=BPoZo2b3r--lPBpURvEDyjyDkS65xBEpmpQhHQvrwlBE;alg=ed25519"'
    )

def test_verify_forwarded_cig():
    # AID and SAID should be the same as what is in credential.cesr for the ECR credential
    # see https://trustoverip.github.io/tswg-acdc-specification/#top-level-fields to understand the fields/values
    AID = "EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x"
    # SAID = "EElnd1DKvcDzzh7u7jBjsg2X9WgdQQuhgiu80i2VR-gk"

    # See https://datatracker.ietf.org/doc/html/rfc9421#section-4.3 for forwarding signed headers
    headers = {
        "HOST": "proxy:3434",
        "CONNECTION": "keep-alive",
        "METHOD": "POST",
        "FORWARDED": "host: localhost:7676",
        "SIGNATURE": 'indexed="?0";signify="0BBbeeBw3lVmQWYBpcFH9KmRXZocrqLH_LZL4aqg5W9-NMdXqIYJ-Sao7colSTJOuYllMXFfggoMhkfpTKnvPhUF"',
        "SIGNATURE-INPUT": 'signify=("@method" "@path" "signify-resource" "signify-timestamp");created=1714854033;keyid="BPoZo2b3r--lPBpURvEDyjyDkS65xBEpmpQhHQvrwlBE";alg="ed25519"',
        "SIGNIFY-RESOURCE": "EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x",
        "SIGNIFY-TIMESTAMP": "2024-05-04T20:20:33.730000+00:00",
        "ACCEPT": "*/*",
        "ACCEPT-LANGUAGE": "*",
        "SEC-FETCH-MODE": "cors",
        "USER-AGENT": "node",
        "ACCEPT-ENCODING": "gzip, deflate",
    }
    scope = dict(type="http", headers=Headers(headers).raw, method="POST", path="/")
    req = fastapi.Request(scope)
    aid, sig, ser = signed_headers_verifier.VerifySignedHeaders.handle_headers(req)
    assert aid == AID
    assert (
        sig
        == "0BBbeeBw3lVmQWYBpcFH9KmRXZocrqLH_LZL4aqg5W9-NMdXqIYJ-Sao7colSTJOuYllMXFfggoMhkfpTKnvPhUF"
    )
    assert (
        ser
        == '"@method": POST\n"@path": /\n"signify-resource": EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x\n"signify-timestamp": 2024-05-04T20:20:33.730000+00:00\n"@signature-params: (@method @path signify-resource signify-timestamp);created=1714854033;keyid=BPoZo2b3r--lPBpURvEDyjyDkS65xBEpmpQhHQvrwlBE;alg=ed25519"'
    )