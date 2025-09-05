# Secure File Manager (CLI + GUI)

A robust file manager written in **C** that provides strong encryption, a personal vault for managing sensitive files, and hashing utilities for verifying file integrity.  

Originally designed as a **command-line application**, it now includes a simple **GTK GUI** for beginners who prefer a graphical interface.  

Cryptography is powered by the industry-standard **OpenSSL** library.

---

## ✨ Features

- **Strong Encryption**: Uses AES-256-CBC for file encryption, ensuring confidentiality.  
- **Secure Key Derivation**: PBKDF2 with SHA-256 + random salt to derive keys from passwords.  
- **Personal Vault**: Local `.vault` directory to store, list, retrieve, and delete encrypted files.  
- **File Integrity**: Hashing utility supporting SHA-256 and SHA-512.  
- **Cross-Platform**: Works on Linux, macOS, and Windows (via WSL).  
- **Now with GUI**: Simple GTK3 interface to perform vault and utility operations without using the terminal.  

---

## 📂 Project Structure

```
secure-file-manager/
├── .vault/          # Auto-generated: Stores encrypted files
├── bin/             # Auto-generated: CLI and GUI executables
│   ├── secure_file_manager   # CLI tool
│   └── secure_gui            # GTK GUI
├── build/           # Auto-generated: Object files (.o)
├── src/             # Source code
│   ├── main.c              # CLI entry point
│   ├── file_manager.c/.h   # Vault operations
│   ├── crypto.c/.h         # Encryption/Decryption + hashing
│   └── gui_gtk.c           # GUI entry point (new)
└── Makefile         # Build script
```

---

## ⚙️ Setup and Prerequisites

### On Linux (Debian/Ubuntu/Kali)
```bash
sudo apt update
sudo apt install build-essential libssl-dev libgtk-3-dev git
```

### On Windows (via WSL)
1. Install WSL (Ubuntu recommended).  
2. Open your WSL terminal.  
3. Install prerequisites:
   ```bash
   sudo apt update
   sudo apt install build-essential libssl-dev libgtk-3-dev git
   ```
4. Navigate to your repo folder (Windows drives are under `/mnt/`).

### On macOS
Using Homebrew:
```bash
brew install gcc make openssl gtk+3 git
```

---

## 🛠️ Building the Project

Clone the repository:
```bash
git clone <your-repository-url>
cd secure-file-manager
```

Build everything (CLI + GUI):
```bash
make
```

- CLI executable → `bin/secure_file_manager`  
- GUI executable → `bin/secure_gui`  

Build only the CLI:
```bash
make cli
```

Build only the GUI:
```bash
make gui
```

Clean build files:
```bash
make clean
```

---

## ▶️ Running the Application

### **1. Command-Line Interface (CLI)**

Create a test file:
```bash
echo "This is my top secret data." > secret_note.txt
```

Vault Commands:
```bash
./bin/secure_file_manager add secret_note.txt MyStrongPassword123
./bin/secure_file_manager list
./bin/secure_file_manager retrieve secret_note.txt.enc decrypted_note.txt MyStrongPassword123
./bin/secure_file_manager delete secret_note.txt.enc MyStrongPassword123
```

Utility Commands:
```bash
./bin/secure_file_manager hash sha256 secret_note.txt
./bin/secure_file_manager hash sha512 secret_note.txt
./bin/secure_file_manager encrypt secret_note.txt manual_encrypted.dat MyStrongPassword123
./bin/secure_file_manager decrypt manual_encrypted.dat manual_decrypted.txt MyStrongPassword123
```

---

### **2. Graphical User Interface (GUI)**

Run:
```bash
./bin/secure_gui
```

The GUI window provides tabs/buttons for:
- **Vault Operations**
  - Add File → encrypt and store in `.vault/`
  - List Files → view encrypted files
  - Retrieve File → decrypt a vault file
  - Delete File → remove from vault
- **Utility Operations**
  - Hash File → choose algorithm (SHA-256/SHA-512)
  - Encrypt/Decrypt → manual operations outside vault

👉 The GUI is intentionally **simple and beginner-friendly**, using text boxes and basic dialogs.

---

## 🧰 Troubleshooting

- `make: command not found` → Install build tools (`sudo apt install build-essential`).  
- `openssl/evp.h: No such file` → Install OpenSSL dev (`sudo apt install libssl-dev`).  
- `gtk/gtk.h: No such file` → Install GTK3 dev (`sudo apt install libgtk-3-dev`).  
- GUI doesn’t open → Run inside a desktop environment (not headless server).  

---

## ✅ Conclusion

The **Secure File Manager** now provides both:
- A **powerful CLI tool** for scripting and advanced users.  
- A **beginner-friendly GUI** using GTK for interactive workflows.  

By leveraging OpenSSL, it ensures confidentiality and integrity of your sensitive files in both terminal and graphical modes.
