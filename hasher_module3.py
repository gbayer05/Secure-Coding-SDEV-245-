#Gentry Bayer 
#September 13th 2026  


import argparse
import hashlib
import sys


def hash_string(text: str) -> str:
    """Return the SHA-256 hex digest of a UTF-8 encoded string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_file(path: str, chunk_size: int = 65536) -> str:
    """Return the SHA-256 hex digest of a file's contents.

    Reads the file in chunks so large files don't need to be
    loaded entirely into memory.
    """
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def interactive_mode():
    print("SHA-256 Hash Generator")
    print("1) Hash a text string")
    print("2) Hash a file")
    choice = input("Choose an option (1/2): ").strip()

    if choice == "1":
        text = input("Enter text to hash: ")
        print(f"\nSHA-256: {hash_string(text)}")
    elif choice == "2":
        path = input("Enter file path: ").strip()
        try:
            print(f"\nSHA-256: {hash_file(path)}")
        except FileNotFoundError:
            print(f"Error: file not found: {path}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Invalid choice.", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Generate SHA-256 hashes for text or files.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--text", help="String to hash")
    group.add_argument("--file", help="Path to file to hash")
    args = parser.parse_args()

    if args.text is not None:
        print(hash_string(args.text))
    elif args.file is not None:
        try:
            print(hash_file(args.file))
        except FileNotFoundError:
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
