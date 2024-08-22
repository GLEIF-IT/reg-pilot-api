import fastapi
from starlette.datastructures import Headers
from regps.app.api.exceptions import VerifySignedHeadersException
from src.regps.app.api import signed_headers_verifier
import pytest


def test_login():
    # AID and SAID should be the same as what is in credential.cesr for the ECR credential
    # see https://trustoverip.github.io/tswg-acdc-specification/#top-level-fields to understand the fields/values
    AID = "EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x"
    # SAID = "EElnd1DKvcDzzh7u7jBjsg2X9WgdQQuhgiu80i2VR-gk"

    # no signed headers needed for login
    headers = {
        "HOST": "localhost:7676",
        "CONNECTION": "keep-alive",
        "METHOD": "POST",
        # "SIGNATURE": 'indexed="?0";signify="0BBbeeBw3lVmQWYBpcFH9KmRXZocrqLH_LZL4aqg5W9-NMdXqIYJ-Sao7colSTJOuYllMXFfggoMhkfpTKnvPhUF"',
        # "SIGNATURE-INPUT": 'signify=("@method" "@path" "signify-resource" "signify-timestamp");created=1714854033;keyid="BPoZo2b3r--lPBpURvEDyjyDkS65xBEpmpQhHQvrwlBE";alg="ed25519"',
        # "SIGNIFY-RESOURCE": "EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x",
        # "SIGNIFY-TIMESTAMP": "2024-05-04T20:20:33.730000+00:00",
        "ACCEPT": "*/*",
        "ACCEPT-LANGUAGE": "*",
        "SEC-FETCH-MODE": "cors",
        "USER-AGENT": "node",
        "ACCEPT-ENCODING": "gzip, deflate",
    }

    scope = dict(type="http", headers=Headers(headers).raw, method="POST", path="/")
    req = fastapi.Request(scope)
    with pytest.raises(VerifySignedHeadersException):
        signed_headers_verifier.VerifySignedHeaders.handle_headers(req)

    headers["SIGNATURE-INPUT"] = (
        'signify=("@method" "@path" "signify-resource" "signify-timestamp");created=1714854033;keyid="BPoZo2b3r--lPBpURvEDyjyDkS65xBEpmpQhHQvrwlBE";alg="ed25519"'
    )
    scope = dict(type="http", headers=Headers(headers).raw, method="POST", path="/")
    req = fastapi.Request(scope)
    with pytest.raises(VerifySignedHeadersException):
        signed_headers_verifier.VerifySignedHeaders.handle_headers(req)

    headers["SIGNATURE"] = (
        'indexed="?0";signify="0BBbeeBw3lVmQWYBpcFH9KmRXZocrqLH_LZL4aqg5W9-NMdXqIYJ-Sao7colSTJOuYllMXFfggoMhkfpTKnvPhUF"'
    )
    scope = dict(type="http", headers=Headers(headers).raw, method="POST", path="/")
    req = fastapi.Request(scope)
    with pytest.raises(VerifySignedHeadersException):
        signed_headers_verifier.VerifySignedHeaders.handle_headers(req)

    headers["SIGNIFY-RESOURCE"] = "EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x"
    scope = dict(type="http", headers=Headers(headers).raw, method="POST", path="/")
    req = fastapi.Request(scope)
    with pytest.raises(VerifySignedHeadersException):
        signed_headers_verifier.VerifySignedHeaders.handle_headers(req)

    headers["SIGNIFY-TIMESTAMP"] = "2024-05-04T20:20:33.730000+00:00"
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
