
# Gentry Bayer 
# SDEV 245 Midterm Assignment
# September 20, 2026 




import base64
import hashlib
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES-GCM: symmetric authenticated encryption


def get_user_input() -> bytes:
    """Accept either typed text or a file path from the user and return bytes."""
    choice = input("Enter (1) to type a message or (2) to load a file: ").strip()

    if choice == "2":
        # Read the file in binary mode so it works for text or non-text files
        path = input("Enter file path: ").strip()
        with open(path, "rb") as f:
            return f.read()

    # Encode the typed string into bytes since hashing/encryption need bytes, not str
    message = input("Type your message: ")
    return message.encode("utf-8")


def sha256_hash(data: bytes) -> str:
    """Return the SHA-256 hex digest of the given data."""
    # hexdigest() gives a readable string version of the hash instead of raw bytes
    return hashlib.sha256(data).hexdigest()


def generate_key() -> bytes:
    """
    Generate a cryptographically secure random 256-bit AES key.

    os.urandom() pulls from the operating system's CSPRNG (e.g. /dev/urandom
    on Linux, CryptGenRandom on Windows), which is seeded from hardware and
    OS entropy sources (timing jitter, interrupts, device noise, etc.).
    High entropy here is what makes the key unpredictable to an attacker.
    """
    # AESGCM.generate_key() handles the secure random generation for us
    return AESGCM.generate_key(bit_length=256)


def generate_nonce() -> bytes:
    """
    Generate a random 96-bit nonce for AES-GCM.

    The nonce must never be reused with the same key. Because it is drawn
    from the same CSPRNG, the probability of collision across many messages
    is negligible in practice for this demo's scale.
    """
    # 12 bytes = 96 bits, the standard/recommended nonce size for AES-GCM
    return os.urandom(12)


def encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.

    GCM is an authenticated encryption mode: it produces ciphertext plus a
    built-in authentication tag, so any tampering with the ciphertext is
    detected on decryption (this is on top of the separate SHA-256 hash
    check we do on the plaintext for this project's requirements).
    """
    aesgcm = AESGCM(key)
    # associated_data=None means we're not authenticating any extra metadata alongside the message
    return aesgcm.encrypt(nonce, plaintext, associated_data=None)


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext back into plaintext."""
    aesgcm = AESGCM(key)
    # Same key + nonce used to encrypt must be used here, or decryption will fail
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def main():
    print("=== Secure Message Demo: SHA-256 + AES-256-GCM ===\n")

    # 1. Get input
    plaintext = get_user_input()
    print(f"\n[Input] {len(plaintext)} bytes read.")

    # 2. Hash the original input (integrity fingerprint)
    original_hash = sha256_hash(plaintext)
    print(f"[Hash]  SHA-256 of original input: {original_hash}")

    # 3. Generate key + nonce and encrypt
    key = generate_key()
    nonce = generate_nonce()
    ciphertext = encrypt(plaintext, key, nonce)

    # Base64-encode the binary key/nonce/ciphertext just so they print as readable text
    print(f"[Key]   Generated 256-bit AES key (base64): {base64.b64encode(key).decode()}")
    print(f"[Nonce] Generated 96-bit nonce (base64): {base64.b64encode(nonce).decode()}")
    print(f"[Enc]   Ciphertext (base64): {base64.b64encode(ciphertext).decode()}")

    # 4. Decrypt and verify integrity
    decrypted = decrypt(ciphertext, key, nonce)
    new_hash = sha256_hash(decrypted)

    print(f"\n[Dec]   Decrypted plaintext: {decrypted.decode(errors='replace')}")
    print(f"[Hash]  SHA-256 of decrypted output: {new_hash}")

    # Compare hashes to confirm the message wasn't altered or corrupted
    if new_hash == original_hash:
        print("\n✅ Integrity verified: hashes match. Message is authentic and unaltered.")
    else:
        print("\n❌ Integrity check FAILED: hashes do not match. Data may be corrupted or tampered with.")
        sys.exit(1)  # Exit with a non-zero status to signal failure


if __name__ == "__main__":
    main()
