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

