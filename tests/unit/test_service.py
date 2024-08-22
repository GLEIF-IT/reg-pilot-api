from fastapi.testclient import TestClient
import logging
from src.regps.app import fastapi_app
import sys

# Create a logger object.
logger = logging.getLogger(__name__)

# Configure the logger to write messages to stdout.
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)

# Set the log level to include all messages.
logger.setLevel(logging.DEBUG)


def test_ends():
    # AID and SAID should be the same as what is in credential.cesr for the ECR credential
    # see https://trustoverip.github.io/tswg-acdc-specification/#top-level-fields to understand the fields/values
    AID = "EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x"
    SAID = "EElnd1DKvcDzzh7u7jBjsg2X9WgdQQuhgiu80i2VR-gk"
    DIG = "EC7b6S50sY26HTj6AtQiWMDMucsBxMvThkmrKUBXVMf0"

    # got these from signify-ts integration test
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

    app = fastapi_app.app
    client = TestClient(app)

    result = client.get("/ping", headers=headers)
    assert result.status_code == 200
    assert result.json() == "Pong"

    with open("./data/credential.cesr", "r") as cfile:
        vlei_ecr = cfile.read()
        headers["Content-Type"] = "application/json"
        result = client.post(
            "/login", json={"said": SAID, "vlei": vlei_ecr}, headers=headers
        )
        assert result.status_code == 202

    result = client.get(f"/checklogin/{AID}", headers=headers)
    assert result.status_code == 200

    result = client.get(f"/upload/{AID}/{DIG}", headers=headers)
    assert result.status_code == 401  # fail because this signature should not verify
