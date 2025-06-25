# LockNest - Terminal Password Vault

> **A secure and modern terminal-based password manager written in Python**, using encrypted vaults, strong cryptography, and a clean Rich-powered interface.

---

## 🔐 Features

* **Master password authentication** (`bcrypt`)
* **Per-user encrypted vaults** (Fernet + HKDF)
* **Full CRUD operations** on password entries
* **Interactive password generator** with strength checker
* **Login lockout system** for brute-force protection
* **Rich-powered terminal UI** with styled menus & panels
* **Fully menu-driven interface**, no command-line arguments

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/LockNest.git
cd LockNest
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

> ✅ **Tip:** Always use a virtual environment to isolate dependencies.

---

## 🚀 Usage

Launch the app:

```bash
python LockNest.py
```

You'll be guided through:

* 🧾 **Registering** or **logging in**
* 🔐 **Accessing your encrypted vault**
* 🔄 **Adding, editing, or deleting entries**
* 🔍 **Searching entries by keyword**

> 🔒 **Passwords are never printed in plaintext in the vault table.**

---

## 📁 Vault Storage

Vaults are stored locally at:

```
~/.locknest/<username>_vault.locknest
```

Each vault is **AES-encrypted**, with a key derived securely from your master password and unique user-based salt.

---

## 📦 Dependencies

Listed in `requirements.txt`:

```text
rich
bcrypt
cryptography
```

Install them with:

```bash
pip install -r requirements.txt
```

---

##  Author

**Ares**



---

## 🪪 License

**MIT License** — free to use, fork, and build upon.
