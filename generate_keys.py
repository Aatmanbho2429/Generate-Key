from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_keys(
    private_key_path: str = "private_key.pem",
    public_key_path: str = "public_key.pem",
):
    # Generate RSA private key (2048-bit)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # Serialize private key (KEEP SECRET)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize public key (EMBED IN APP)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(private_key_path, "wb") as f:
        f.write(private_pem)

    with open(public_key_path, "wb") as f:
        f.write(public_pem)

    print("✅ RSA keys generated")
    print(f" - {private_key_path}  (KEEP SECRET)")
    print(f" - {public_key_path}   (EMBED IN APP)")


if __name__ == "__main__":
    generate_keys()
