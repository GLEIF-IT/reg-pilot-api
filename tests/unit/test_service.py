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
    AID = "EC3Rm0f9aQiZz2hxZOIup5Soyu6x_aA5996LP-eN6hBu"
    SAID = "EHw8lEt5PmJZa-_eFdjxBNNUw4f8l3pT5lAZAQNc__SI"
    DIG = "sha256-ba486c1a6249b804cdb0e163d84ed1309db776aded2ac4b5cb17f41929d3ca85"

    # got these from signify-ts integration test
    headers = {
        "HOST": "localhost:7676",
        "CONNECTION": "keep-alive",
        "METHOD": "POST",
        "SIGNATURE": 'indexed="?0";signify="0BAo0wmWUJRG6a_-kmdeYWRhVdjifc9Dp7cEWxpFpLp4fUf114pb7Qec3r43uqGWfQdu33ci5PTDFgcIiDjsDPMI"',
        "SIGNATURE-INPUT": 'signify=("@method" "@path" "signify-resource" "signify-timestamp");created=1737497943;keyid="BAIGwtGP4CFwVqXiU9bspN5_eoWpPfNh9qChkK6FtDAu";alg="ed25519"',
        "SIGNIFY-RESOURCE": 'EC3Rm0f9aQiZz2hxZOIup5Soyu6x_aA5996LP-eN6hBu',
        "SIGNIFY-TIMESTAMP": "2025-01-21T22:19:03.646000+00:00",
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
    assert result.status_code == 401 # 401 because the QVI delegator is not Root Of Trust
    # assert result.text == '{"aid":"EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x","said":"EElnd1DKvcDzzh7u7jBjsg2X9WgdQQuhgiu80i2VR-gk","lei":"875500ELOZEL05BVXV37","msg":"AID EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x w/ lei 875500ELOZEL05BVXV37 has valid login account"}'

    result = client.get(f"/upload/{AID}/{DIG}", headers=headers)
    assert result.status_code == 401  # fail because this signature should not verify
