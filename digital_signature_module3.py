#Gentry Bayer 
#September 13th 2026  


import argparse
import os
import subprocess
import sys
import tempfile


def run(cmd):
    """Run a shell command, streaming output, and raise on failure."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")
    return result.stdout.strip()


def generate_keypair(out_dir: str, key_size: int = 2048):
    os.makedirs(out_dir, exist_ok=True)
    private_key = os.path.join(out_dir, "private.pem")
    public_key = os.path.join(out_dir, "public.pem")

    run(["openssl", "genpkey", "-algorithm", "RSA",
         "-pkeyopt", f"rsa_keygen_bits:{key_size}",
         "-out", private_key])
    run(["openssl", "pkey", "-in", private_key,
         "-pubout", "-out", public_key])

    print(f"Private key written to: {private_key}")
    print(f"Public key written to:  {public_key}")
    return private_key, public_key


def sign_file(file_path: str, private_key_path: str, sig_path: str):
    run(["openssl", "dgst", "-sha256", "-sign", private_key_path,
         "-out", sig_path, file_path])
    print(f"Signature written to: {sig_path}")


def verify_file(file_path: str, public_key_path: str, sig_path: str) -> bool:
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", public_key_path,
         "-signature", sig_path, file_path],
        capture_output=True, text=True,
    )
    output = (result.stdout + result.stderr).strip()
    ok = result.returncode == 0 and "Verified OK" in output
    print(output)
    return ok


def demo():
    """Run the full generate -> sign -> verify -> tamper-check workflow."""
    with tempfile.TemporaryDirectory() as tmp:
        key_dir = os.path.join(tmp, "keys")
        message_path = os.path.join(tmp, "message.txt")
        sig_path = os.path.join(tmp, "message.sig")

        print("=== Step 1: Generate RSA key pair ===")
        private_key, public_key = generate_keypair(key_dir)

        print("\n=== Step 2: Create a sample message ===")
        with open(message_path, "w") as f:
            f.write("This message is authentic and has not been tampered with.\n")
        print(f"Message written to: {message_path}")

        print("\n=== Step 3: Sign the message with the private key ===")
        sign_file(message_path, private_key, sig_path)

        print("\n=== Step 4: Verify the signature with the public key ===")
        valid = verify_file(message_path, public_key, sig_path)
        print(f"Result: {'VALID signature' if valid else 'INVALID signature'}")

        print("\n=== Step 5: Tamper with the message and verify again ===")
        with open(message_path, "a") as f:
            f.write("Extra malicious line.\n")
        valid_after_tamper = verify_file(message_path, public_key, sig_path)
        print(f"Result: {'VALID signature' if valid_after_tamper else 'INVALID signature (tampering detected)'}")


def main():
    parser = argparse.ArgumentParser(description="Digital signature sign/verify tool (OpenSSL-backed).")
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("genkey", help="Generate an RSA key pair")
    p_gen.add_argument("--out-dir", default="keys", help="Directory to write keys to")
    p_gen.add_argument("--key-size", type=int, default=2048)

    p_sign = sub.add_parser("sign", help="Sign a file")
    p_sign.add_argument("--file", required=True)
    p_sign.add_argument("--key", required=True, help="Path to private key")
    p_sign.add_argument("--sig", required=True, help="Output path for signature")

    p_verify = sub.add_parser("verify", help="Verify a file's signature")
    p_verify.add_argument("--file", required=True)
    p_verify.add_argument("--key", required=True, help="Path to public key")
    p_verify.add_argument("--sig", required=True, help="Path to signature file")

    sub.add_parser("demo", help="Run the full sign/verify workflow with sample data")

    args = parser.parse_args()

    if args.command == "genkey":
        generate_keypair(args.out_dir, args.key_size)
    elif args.command == "sign":
        sign_file(args.file, args.key, args.sig)
    elif args.command == "verify":
        ok = verify_file(args.file, args.key, args.sig)
        sys.exit(0 if ok else 1)
    elif args.command == "demo":
        demo()


if __name__ == "__main__":
    main()
