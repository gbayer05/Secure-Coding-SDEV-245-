#Gentry Bayer 
#September 13th 2026  


import argparse
import sys

ALPHABET_SIZE = 26


def shift_char(ch: str, shift: int) -> str:
    """Shift a single character by `shift` positions, wrapping around
    the alphabet. Non-letters are returned unchanged."""
    if ch.isupper():
        base = ord("A")
    elif ch.islower():
        base = ord("a")
    else:
        return ch
    return chr((ord(ch) - base + shift) % ALPHABET_SIZE + base)


def encrypt(text: str, shift: int) -> str:
    return "".join(shift_char(c, shift) for c in text)


def decrypt(text: str, shift: int) -> str:
    return "".join(shift_char(c, -shift) for c in text)


def brute_force(text: str):
    """Print all 26 possible shifts, useful if the key is unknown."""
    for s in range(ALPHABET_SIZE):
        print(f"Shift {s:2d}: {decrypt(text, s)}")


def interactive_mode():
    print("Caesar Cipher Tool")
    print("1) Encrypt")
    print("2) Decrypt")
    print("3) Brute-force decrypt (try all shifts)")
    choice = input("Choose an option (1/2/3): ").strip()
    text = input("Enter text: ")

    if choice == "3":
        brute_force(text)
        return

    try:
        shift = int(input("Enter shift value (integer): ").strip())
    except ValueError:
        print("Shift must be an integer.", file=sys.stderr)
        sys.exit(1)

    if choice == "1":
        print(f"\nEncrypted: {encrypt(text, shift)}")
    elif choice == "2":
        print(f"\nDecrypted: {decrypt(text, shift)}")
    else:
        print("Invalid choice.", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Caesar cipher encrypt/decrypt tool.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--encrypt", action="store_true", help="Encrypt the text")
    mode.add_argument("--decrypt", action="store_true", help="Decrypt the text")
    mode.add_argument("--brute-force", action="store_true", help="Try all 26 shifts")
    parser.add_argument("--shift", type=int, help="Shift value (required for encrypt/decrypt)")
    parser.add_argument("--text", help="Text to process")
    args = parser.parse_args()

    if not (args.encrypt or args.decrypt or args.brute_force):
        interactive_mode()
        return

    if args.text is None:
        print("Error: --text is required.", file=sys.stderr)
        sys.exit(1)

    if args.brute_force:
        brute_force(args.text)
        return

    if args.shift is None:
        print("Error: --shift is required for encrypt/decrypt.", file=sys.stderr)
        sys.exit(1)

    if args.encrypt:
        print(encrypt(args.text, args.shift))
    elif args.decrypt:
        print(decrypt(args.text, args.shift))


if __name__ == "__main__":
    main()