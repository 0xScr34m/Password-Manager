# 🔐 Password Manager

A simple command-line password manager that generates, stores, and retrieves passwords securely.

## ✨ Features

- 🔑 Generate strong random passwords with customizable options
- 💾 Store passwords with basic encryption
- 🔍 Retrieve passwords when needed
- 📋 List all stored passwords and services
- 🗑️ Delete passwords you no longer need
- 🔄 Change your master password anytime
- 🔒 Local storage with file permission protection

## 🚀 Installation

1. Clone this repository:
```bash
git clone https://github.com/0xScr34m/password-manager.git
cd password-manager
```

2. Make the script executable (Unix/Linux/macOS):
```bash
chmod +x main.py
```

## 🔍 Usage

```bash
python main.py <command> [options]
```

## ⚙️ Commands

- `generate`: Generate a random password
- `add`: Add or update a password
- `get`: Retrieve a password
- `list`: List all stored services
- `delete`: Delete a stored password
- `change-master`: Change the master password

## 📋 Command Options

### Generate a password:
```bash
python main.py generate [options]
```

#### Options:

- `-l, --length`: Password length (default: 16)
- `--no-upper`: Don't include uppercase letters
- `--no-lower`: Don't include lowercase letters
- `--no-digits`: Don't include digits
- `--no-symbols`: Don't include symbols
- `--no-similar`: Don't include similar characters (Il1O0o)

### Add or update a password:
```bash
python main.py add <service> <username> [options]
```

#### Options:

- `-p, --password`: Password (if not provided, you'll be prompted)
- `-g, --generate`: Generate a password
- `-l, --length`: Generated password length (default: 16)

### Retrieve a password:
```bash
python main.py get <service>
```

### List all services:
```bash
python main.py list
```

### Delete a password:
```bash
python main.py delete <service>
```

### Change master password:
```bash
python main.py change-master
```

### Global options:

- `-f, --file`: Password storage file (default: ~/.password_store.json)

## 📝 Examples

### Generate a password:
```bash
python main.py generate
```

### Generate a custom password:
```bash
python main.py generate -l 20 --no-symbols
```

### Add a password:
```bash
python main.py add gmail user@example.com
```

### Add with an auto-generated password:
```bash
python main.py add github username -g -l 24
```

### Retrieve a password:
```bash
python main.py get gmail
```

### List all stored passwords:
```bash
python main.py list
```

### Delete a password:
```bash
python main.py delete old-account
```

### Change your master password:
```bash
python main.py change-master
```

## 🔒 Security Information

This password manager uses:
- Encrypted storage of your passwords using a master password
- Basic XOR-based encryption with multiple iterations
- Local storage of passwords (no cloud sync)
- File permission restrictions (readable only by you)

### Security Limitations:

This is a simple password manager for educational purposes and has several limitations:
- The encryption method is not as strong as industry standards like AES
- The master password is vulnerable to brute-force attacks
- No protection against memory attacks
- No backup or synchronization features

For critical accounts, consider using a professional password manager with stronger security features.

## 💡 Tips

- Use a long, complex master password that you can remember
- Make backups of your password file (`~/.password_store.json` by default)
- For maximum security, use long passwords with all character types
- The `list` command only shows service names and usernames, not the actual passwords
- You can store other sensitive information in the password field, not just passwords

