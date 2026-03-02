from cryptography.hazmat.primitives import hashes

def sha256_hash(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()
