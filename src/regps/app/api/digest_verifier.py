from hashlib import sha256
from regps.app.api.exceptions import DigestVerificationFailedException


def get_non_prefixed_digest(dig):
    try:
        prefix, digest = dig.split("_", 1)
    except ValueError:
        raise DigestVerificationFailedException(
            f"Digest ({dig}) must start with prefix", 400
        )
    return digest


def verify_digest(file: bytes, digest: str):
    digest = get_non_prefixed_digest(digest)
    actual_digest = sha256(file).hexdigest()
    return actual_digest == digest
