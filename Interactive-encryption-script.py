from cryptography.fernet import Fernet
from pathlib import Path
import getpass


def generate_key(key_path: Path):
    """
    Generates a new Fernet key and overwrites if it already exists.
    """
    key = Fernet.generate_key()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key)
    print(f"Key generated (overwritten if existed) at: {key_path}")


def encrypt_password(key_path: Path, output_path: Path, show_encrypted: bool = False):
    """
    Encrypts a password entered interactively and overwrites output file.
    Optionally displays the encrypted password string.
    """
    if not key_path.exists():
        print("Key file not found. Generating a new one...")
        generate_key(key_path)

    password = getpass.getpass("Enter your password: ")

    key = key_path.read_bytes()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(password.encode())

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encrypted)

    print(f"Encrypted password saved (overwritten if existed) at: {output_path}")

    if show_encrypted:
        print(f"\nEncrypted password (base64):\n{encrypted.decode()}")


def view_password(key_path: Path, encrypted_path: Path):
    """
    Decrypts and displays the stored password using the key file.
    """
    if not key_path.exists():
        print(f"Error: Key file not found at: {key_path}")
        return
    if not encrypted_path.exists():
        print(f"Error: Encrypted password file not found at: {encrypted_path}")
        return

    try:
        key = key_path.read_bytes()
        encrypted = encrypted_path.read_bytes()

        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted).decode()

        print("\n--- Decrypted Password ---")
        print(f"Password: {decrypted}")
        print("--------------------------")

        show_raw = input("Also show raw encrypted token? (y/n): ").strip().lower()
        if show_raw == 'y':
            print(f"\nEncrypted token (base64):\n{encrypted.decode()}")

    except Exception as e:
        print(f"\n[ERROR] Failed to decrypt: {type(e).__name__}: {e}")
        print("Hint: The key file does not match the encrypted file.")
        print("      If you re-generated the key after encrypting, the old password is unrecoverable.")


def get_folder_path() -> Path:
    """
    Prompts user to select a folder location.
    """
    default_secrets = Path.cwd() / ".secrets"
    print("\n--- Folder Location ---")
    print(f"1. Use current directory's .secrets folder  ({default_secrets})")
    print("2. Enter a custom folder path")

    loc_choice = input("Choose folder option (1/2): ").strip()

    if loc_choice == "1":
        return default_secrets
    elif loc_choice == "2":
        folder_input = input("Enter folder path to store files: ").strip()
        return Path(folder_input)
    else:
        print("Invalid choice, defaulting to .secrets folder.")
        return default_secrets


def get_show_encrypted() -> bool:
    show = input("\nShow encrypted password after encrypting? (y/n): ").strip().lower()
    return show == 'y'


def main():
    print("=== Secure Password Encryption Tool ===")

    base_path = get_folder_path()
    key_file = base_path / ".fernet.key"
    password_file = base_path / ".password.enc"

    print("\n1. Generate Key")
    print("2. Encrypt Password")
    print("3. Generate Key + Encrypt Password (recommended)")
    print("4. View / Decrypt existing password")
    choice = input("Choose an option (1/2/3/4): ").strip()

    if choice == "1":
        generate_key(key_file)

    elif choice == "2":
        show_encrypted = get_show_encrypted()
        encrypt_password(key_file, password_file, show_encrypted)

    elif choice == "3":
        # Warn if existing files would be overwritten — new key breaks old encrypted file
        if key_file.exists() and password_file.exists():
            print("\nWARNING: A key and encrypted password already exist.")
            print("  Re-generating the key will make the existing encrypted password UNRECOVERABLE.")
            confirm = input("  Continue and overwrite both? (y/n): ").strip().lower()
            if confirm != 'y':
                print("Aborted.")
                return
        show_encrypted = get_show_encrypted()
        generate_key(key_file)
        encrypt_password(key_file, password_file, show_encrypted)

    elif choice == "4":
        view_password(key_file, password_file)

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
