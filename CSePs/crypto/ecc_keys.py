from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, filepath, password=None):
    if password:
        encryption_alg = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption_alg = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_alg
    )
    with open(filepath, "wb") as f:
        f.write(pem)


def save_public_key(public_key, filepath):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filepath, "wb") as f:
        f.write(pem)
        

def load_private_key(filepath, password=None):
    with open(filepath, "rb") as f:
        pwd_bytes = password.encode() if password else None
        return serialization.load_pem_private_key(
            f.read(),
            password=pwd_bytes
        )


def load_public_key(filepath):
    with open(filepath, "rb") as f:
        return serialization.load_pem_public_key(
            f.read()
        )