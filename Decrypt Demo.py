# Encrypt/Decrypt Demo
# Gentry Bayer 
# 9/7/2026 


from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64


def symmetric_demo(message: str) -> dict:
    """Encrypt/decrypt using AES via Fernet. Same key locks and unlocks."""

    # Generate a random secret key (already base64-encoded, safe to print)
    key = Fernet.generate_key()
    f = Fernet(key)

    # Encrypt: string -> bytes -> ciphertext token
    ciphertext = f.encrypt(message.encode())

    # Decrypt with the SAME key
    plaintext = f.decrypt(ciphertext).decode()

    return {
        "method": "Symmetric (AES via Fernet)",
        "key": key.decode(),
        "input": message,
        "ciphertext": ciphertext.decode(),
        "output": plaintext,
    }


def asymmetric_demo(message: str) -> dict:
    """Encrypt/decrypt using RSA. Public key encrypts, private key decrypts."""

    # Generate key pair (2048-bit, standard exponent)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # OAEP padding is required for secure RSA (raw RSA alone isn't safe)
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    # Encrypt with the public key (shareable)
    ciphertext = public_key.encrypt(message.encode(), oaep)

    # Decrypt with the private key (secret)
    plaintext = private_key.decrypt(ciphertext, oaep).decode()

    # Convert keys to readable PEM text for display/storage
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return {
        "method": "Asymmetric (RSA-2048 + OAEP)",
        "public_key": public_pem,
        "private_key": private_pem,
        "input": message,
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),  # bytes -> text
        "output": plaintext,
    }


def format_report(sym: dict, asym: dict) -> str:
    """Combine both results into one readable text report."""
    lines = []

    lines.append("=" * 70)
    lines.append("SYMMETRIC ENCRYPTION DEMO (Fernet / AES-128)")
    lines.append("=" * 70)
    lines.append(f"Key (shared secret):\n{sym['key']}\n")
    lines.append(f"Input message:\n{sym['input']}\n")
    lines.append(f"Ciphertext (base64, Fernet token):\n{sym['ciphertext']}\n")
    lines.append(f"Decrypted output:\n{sym['output']}\n")

    lines.append("=" * 70)
    lines.append("ASYMMETRIC ENCRYPTION DEMO (RSA-2048 + OAEP)")
    lines.append("=" * 70)
    lines.append(f"Public key (used to encrypt):\n{asym['public_key']}")
    lines.append(f"Private key (used to decrypt):\n{asym['private_key']}")
    lines.append(f"Input message:\n{asym['input']}\n")
    lines.append(f"Ciphertext (base64):\n{asym['ciphertext_b64']}\n")
    lines.append(f"Decrypted output:\n{asym['output']}\n")

    return "\n".join(lines)


if __name__ == "__main__":
    # Same message run through both methods, for a fair comparison
    message = "Hello, this is a secret message!"

    sym_result = symmetric_demo(message)
    asym_result = asymmetric_demo(message)
    report = format_report(sym_result, asym_result)

    print(report)

    # Save as evidence: keys, inputs, and outputs
    with open("output.txt", "w") as f:
        f.write(report)

    print("\n[+] Full report also saved to output.txt")