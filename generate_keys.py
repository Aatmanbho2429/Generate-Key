from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_keys():
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Extract public key
    public_key = private_key.public_key()

    # Serialize private key (KEEP THIS SECRET)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key (SAFE TO SHARE)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write keys to files
    with open("private_key.pem", "wb") as f:
        f.write(private_pem)

    with open("public_key.pem", "wb") as f:
        f.write(public_pem)

    print("Keys generated successfully.")
    print(" - private_key.pem  (KEEP SECRET)")
    print(" - public_key.pem   (EMBED IN APP)")


if __name__ == "__main__":
    generate_keys()
