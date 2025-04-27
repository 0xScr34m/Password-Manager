#!/usr/bin/env python3

import argparse
import base64
import getpass
import json
import os
import random
import string
import sys
from datetime import datetime
from hashlib import sha256
from pathlib import Path

# Constants
DEFAULT_PASSWORD_LENGTH = 16
DEFAULT_STORAGE_FILE = os.path.expanduser("~/.password_store.json")
ENCRYPTION_ITERATIONS = 10000

def generate_password(length=DEFAULT_PASSWORD_LENGTH, use_uppercase=True, 
                    use_lowercase=True, use_digits=True, use_symbols=True, 
                    no_similar=False):
    """Generate a random password with specified options"""
    # Define character sets
    uppercase_chars = string.ascii_uppercase
    lowercase_chars = string.ascii_lowercase
    digit_chars = string.digits
    symbol_chars = string.punctuation
    
    # Remove similar characters if requested
    if no_similar:
        similar_chars = "Il1O0o"
        uppercase_chars = ''.join(c for c in uppercase_chars if c not in similar_chars)
        lowercase_chars = ''.join(c for c in lowercase_chars if c not in similar_chars)
        digit_chars = ''.join(c for c in digit_chars if c not in similar_chars)
    
    # Build character pool based on options
    char_pool = ""
    if use_uppercase:
        char_pool += uppercase_chars
    if use_lowercase:
        char_pool += lowercase_chars
    if use_digits:
        char_pool += digit_chars
    if use_symbols:
        char_pool += symbol_chars
    
    # Ensure at least one character type is selected
    if not char_pool:
        print("Error: At least one character type must be enabled")
        return None
    
    # Generate password
    password = ''.join(random.choice(char_pool) for _ in range(length))
    
    return password

def derive_key(master_password):
    """Derive an encryption key from the master password"""
    # Simple key derivation using SHA-256
    return sha256(master_password.encode()).digest()

def encrypt(data, key):
    """Encrypt data using a simple XOR-based encryption"""
    # Convert data to bytes if it's a string
    if isinstance(data, str):
        data = data.encode()
    
    # Convert data to bytes and encrypt with XOR
    key_bytes = bytearray(key)
    encrypted = bytearray(data)
    
    for i in range(len(encrypted)):
        encrypted[i] ^= key_bytes[i % len(key_bytes)]
    
    # Apply multiple rounds of encryption
    for _ in range(ENCRYPTION_ITERATIONS % 100):  # Limit to reasonable number
        for i in range(len(encrypted)):
            encrypted[i] ^= key_bytes[(i + encrypted[(i - 1) % len(encrypted)]) % len(key_bytes)]
    
    # Return base64 encoded result
    return base64.b64encode(encrypted).decode()

def decrypt(encrypted_data, key):
    """Decrypt data using the same XOR-based encryption"""
    try:
        # Decode base64
        encrypted = base64.b64decode(encrypted_data)
        
        # Convert to bytearray for manipulation
        decrypted = bytearray(encrypted)
        key_bytes = bytearray(key)
        
        # Reverse the multi-round encryption
        for _ in range(ENCRYPTION_ITERATIONS % 100):  # Same limit as encryption
            for i in range(len(decrypted) - 1, -1, -1):
                decrypted[i] ^= key_bytes[(i + decrypted[(i - 1) % len(decrypted)]) % len(key_bytes)]
        
        # Apply basic XOR decryption
        for i in range(len(decrypted)):
            decrypted[i] ^= key_bytes[i % len(key_bytes)]
        
        # Return decoded result
        return decrypted.decode()
    except Exception as e:
        return None

def load_passwords(master_password, storage_file=DEFAULT_STORAGE_FILE):
    """Load stored passwords"""
    if not os.path.exists(storage_file):
        return {}
    
    try:
        with open(storage_file, 'r') as f:
            encrypted_data = f.read().strip()
        
        if not encrypted_data:
            return {}
        
        key = derive_key(master_password)
        json_data = decrypt(encrypted_data, key)
        
        if json_data is None:
            print("Error: Incorrect master password or corrupted data")
            return None
        
        return json.loads(json_data)
    except json.JSONDecodeError:
        print("Error: Corrupted password store")
        return None
    except Exception as e:
        print(f"Error loading passwords: {e}")
        return None

def save_passwords(passwords, master_password, storage_file=DEFAULT_STORAGE_FILE):
    """Save passwords to the storage file"""
    try:
        # Create directory if it doesn't exist
        storage_dir = os.path.dirname(storage_file)
        if storage_dir and not os.path.exists(storage_dir):
            os.makedirs(storage_dir)
        
        key = derive_key(master_password)
        json_data = json.dumps(passwords)
        encrypted_data = encrypt(json_data, key)
        
        with open(storage_file, 'w') as f:
            f.write(encrypted_data)
        
        # Set secure permissions on storage file
        os.chmod(storage_file, 0o600)
        
        return True
    except Exception as e:
        print(f"Error saving passwords: {e}")
        return False

def add_password(service, username, password, master_password, storage_file=DEFAULT_STORAGE_FILE):
    """Add or update a password"""
    passwords = load_passwords(master_password, storage_file)
    if passwords is None:
        return False
    
    # Create entry
    entry = {
        "username": username,
        "password": password,
        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Update if exists
    if service in passwords:
        entry["created"] = passwords[service]["created"]
        entry["modified"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    passwords[service] = entry
    
    return save_passwords(passwords, master_password, storage_file)

def get_password(service, master_password, storage_file=DEFAULT_STORAGE_FILE):
    """Retrieve a password for a service"""
    passwords = load_passwords(master_password, storage_file)
    if passwords is None:
        return None
    
    return passwords.get(service)

def list_services(master_password, storage_file=DEFAULT_STORAGE_FILE):
    """List all services with stored passwords"""
    passwords = load_passwords(master_password, storage_file)
    if passwords is None:
        return None
    
    return passwords

def delete_password(service, master_password, storage_file=DEFAULT_STORAGE_FILE):
    """Delete a stored password"""
    passwords = load_passwords(master_password, storage_file)
    if passwords is None:
        return False
    
    if service not in passwords:
        print(f"Service '{service}' not found")
        return False
    
    del passwords[service]
    
    return save_passwords(passwords, master_password, storage_file)

def change_master_password(old_master, new_master, storage_file=DEFAULT_STORAGE_FILE):
    """Change the master password"""
    passwords = load_passwords(old_master, storage_file)
    if passwords is None:
        return False
    
    return save_passwords(passwords, new_master, storage_file)

def main():
    parser = argparse.ArgumentParser(description="Simple Password Manager")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Generate password command
    generate_parser = subparsers.add_parser("generate", help="Generate a random password")
    generate_parser.add_argument("-l", "--length", type=int, default=DEFAULT_PASSWORD_LENGTH, 
                              help=f"Password length (default: {DEFAULT_PASSWORD_LENGTH})")
    generate_parser.add_argument("--no-upper", action="store_true", help="Don't include uppercase letters")
    generate_parser.add_argument("--no-lower", action="store_true", help="Don't include lowercase letters")
    generate_parser.add_argument("--no-digits", action="store_true", help="Don't include digits")
    generate_parser.add_argument("--no-symbols", action="store_true", help="Don't include symbols")
    generate_parser.add_argument("--no-similar", action="store_true", 
                              help="Don't include similar characters (Il1O0o)")
    
    # Add password command
    add_parser = subparsers.add_parser("add", help="Add or update a password")
    add_parser.add_argument("service", help="Service or website name")
    add_parser.add_argument("username", help="Username or email")
    add_parser.add_argument("-p", "--password", help="Password (if not provided, will be generated)")
    add_parser.add_argument("-g", "--generate", action="store_true", help="Generate a password")
    add_parser.add_argument("-l", "--length", type=int, default=DEFAULT_PASSWORD_LENGTH, 
                         help=f"Generated password length (default: {DEFAULT_PASSWORD_LENGTH})")
    
    # Get password command
    get_parser = subparsers.add_parser("get", help="Retrieve a password")
    get_parser.add_argument("service", help="Service or website name")
    
    # List services command
    list_parser = subparsers.add_parser("list", help="List all stored services")
    
    # Delete password command
    delete_parser = subparsers.add_parser("delete", help="Delete a stored password")
    delete_parser.add_argument("service", help="Service or website name")
    
    # Change master password command
    change_master_parser = subparsers.add_parser("change-master", help="Change the master password")
    
    # Global options
    parser.add_argument("-f", "--file", default=DEFAULT_STORAGE_FILE, 
                       help=f"Password storage file (default: {DEFAULT_STORAGE_FILE})")
    
    args = parser.parse_args()
    
    if args.command == "generate":
        password = generate_password(
            length=args.length,
            use_uppercase=not args.no_upper,
            use_lowercase=not args.no_lower,
            use_digits=not args.no_digits,
            use_symbols=not args.no_symbols,
            no_similar=args.no_similar
        )
        
        if password:
            print(f"Generated password: {password}")
    
    elif args.command == "add":
        # Get master password
        master_password = getpass.getpass("Enter master password: ")
        
        # Determine password to store
        if args.password:
            password = args.password
        elif args.generate:
            password = generate_password(length=args.length)
            if not password:
                return
        else:
            password = getpass.getpass("Enter password to store: ")
        
        if add_password(args.service, args.username, password, master_password, args.file):
            print(f"Password for {args.service} stored successfully")
            if args.generate:
                print(f"Generated password: {password}")
    
    elif args.command == "get":
        # Get master password
        master_password = getpass.getpass("Enter master password: ")
        
        entry = get_password(args.service, master_password, args.file)
        if entry:
            print(f"\nService: {args.service}")
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
            print(f"Created: {entry['created']}")
            print(f"Last modified: {entry['modified']}")
        else:
            print(f"No entry found for {args.service}")
    
    elif args.command == "list":
        # Get master password
        master_password = getpass.getpass("Enter master password: ")
        
        services = list_services(master_password, args.file)
        if services:
            print("\nStored services:")
            print("-" * 50)
            for service, entry in sorted(services.items()):
                print(f"{service} - {entry['username']} (Modified: {entry['modified']})")
            print("-" * 50)
            print(f"Total: {len(services)} services")
        else:
            print("No stored passwords found")
    
    elif args.command == "delete":
        # Get master password
        master_password = getpass.getpass("Enter master password: ")
        
        if delete_password(args.service, master_password, args.file):
            print(f"Password for {args.service} deleted successfully")
    
    elif args.command == "change-master":
        # Get old master password
        old_master = getpass.getpass("Enter current master password: ")
        
        # Get new master password
        new_master = getpass.getpass("Enter new master password: ")
        confirm_master = getpass.getpass("Confirm new master password: ")
        
        if new_master != confirm_master:
            print("Error: Passwords do not match")
            return
        
        if change_master_password(old_master, new_master, args.file):
            print("Master password changed successfully")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
