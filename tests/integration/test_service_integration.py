from fastapi.testclient import TestClient
import logging
from src.regps.app import fastapi_app
import pytest
import sys
import time
import threading
from wsgiref import simple_server

# Create a logger object.
logger = logging.getLogger(__name__)

# Configure the logger to write messages to stdout.
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)

# Set the log level to include all messages.
logger.setLevel(logging.DEBUG)


@pytest.fixture(scope="session")
def start_gunicorn():
    # Start Gunicorn server in a separate thread
    server = simple_server.make_server("0.0.0.0", 8000, fastapi_app.app)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    # Give it some time to start up
    time.sleep(3)
    yield
    # Stop Gunicorn server after tests have finished
    server.shutdown()
    server_thread.join()


@pytest.mark.manual
def test_service_integration(start_gunicorn):
    logger.info("Running test_local so that you can debug the server")
    while True:
        time.sleep(1)


# TODO use this test as a basis for an integration test (rather than simulated unit test)
# currently needs a pre-loaded vlei-verifier populated per signify-ts vlei-verifier test
@pytest.mark.manual
def test_ends_integration(start_gunicorn):
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
    assert result.text == "Pong"

    with open("../../data/credential.cesr", "r") as cfile:
        vlei_ecr = cfile.read()
        headers["Content-Type"] = "application/json+cesr"
        result = client.post(
            "/login", json={"said": SAID, "vlei": vlei_ecr}, headers=headers
        )
        assert result.status_code == 202

    result = client.get(f"/checklogin/{AID}", headers=headers)
    assert result.status_code == 200

    result = client.get(f"/checkupload/{AID}/{DIG}", headers=headers)
    assert (
        result.status_code == result.status_code == 401
    )  # fail because this signature should not verify
