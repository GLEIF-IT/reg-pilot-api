import falcon
from falcon.testing import create_environ
from regps.app import service
from regps.app import tasks
from keri.core import coring

import pytest

# @pytest.fixture(autouse=True)
# def setup():
#     # Your setup code goes here
#     print("Setting up")

def test_login():        
    #AID and SAID should be the same as what is in credential.cesr for the ECR credential
    #see https://trustoverip.github.io/tswg-acdc-specification/#top-level-fields to understand the fields/values
    AID="EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x"
    SAID="EElnd1DKvcDzzh7u7jBjsg2X9WgdQQuhgiu80i2VR-gk"
    
    #no signed headers needed for login
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
    
    verCig = service.VerifySignedHeaders()

    env = create_environ(headers=headers, method='POST', path='/')
    req = falcon.Request(env)
    assert verCig.handle_headers(req) == False

    headers["SIGNATURE-INPUT"]='signify=("@method" "@path" "signify-resource" "signify-timestamp");created=1714854033;keyid="BPoZo2b3r--lPBpURvEDyjyDkS65xBEpmpQhHQvrwlBE";alg="ed25519"'
    env = create_environ(headers=headers, method='POST', path='/')
    req = falcon.Request(env)
    assert verCig.handle_headers(req) == False

    headers["SIGNATURE"]='indexed="?0";signify="0BBbeeBw3lVmQWYBpcFH9KmRXZocrqLH_LZL4aqg5W9-NMdXqIYJ-Sao7colSTJOuYllMXFfggoMhkfpTKnvPhUF"'
    env = create_environ(headers=headers, method='POST', path='/')
    req = falcon.Request(env)
    assert verCig.handle_headers(req) == False
    
    headers["SIGNIFY-RESOURCE"]="EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x"
    env = create_environ(headers=headers, method='POST', path='/')
    req = falcon.Request(env)
    assert verCig.handle_headers(req) == False

    headers["SIGNIFY-TIMESTAMP"]="2024-05-04T20:20:33.730000+00:00"
    env = create_environ(headers=headers, method='POST', path='/')
    req = falcon.Request(env)
    aid, sig, ser = verCig.handle_headers(req)
    
    assert aid == AID
    assert sig == "0BBbeeBw3lVmQWYBpcFH9KmRXZocrqLH_LZL4aqg5W9-NMdXqIYJ-Sao7colSTJOuYllMXFfggoMhkfpTKnvPhUF"
    assert ser == '"@method": POST\n"@path": /\n"signify-resource": EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x\n"signify-timestamp": 2024-05-04T20:20:33.730000+00:00\n"@signature-params: (@method @path signify-resource signify-timestamp);created=1714854033;keyid=BPoZo2b3r--lPBpURvEDyjyDkS65xBEpmpQhHQvrwlBE;alg=ed25519"'