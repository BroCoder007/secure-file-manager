Secure Command-Line File Manager
A robust, command-line tool written in C for securing files through strong encryption. It provides a personal vault for managing sensitive files and includes hashing utilities for verifying file integrity. The application uses the industry-standard OpenSSL library for all cryptographic operations.

Features
Strong Encryption: Utilizes AES-256-CBC for file encryption, ensuring confidentiality.

Secure Key Derivation: Uses PBKDF2 with SHA-256 and a random salt to derive encryption keys from user passwords, protecting against rainbow table attacks.

Personal Vault: A simple, local vault system (.vault directory) to add, list, retrieve, and delete encrypted files easily.

File Integrity: Includes a hashing utility to generate SHA-256 or SHA-512 hashes of any file, allowing users to verify that files have not been tampered with.

Cross-Platform: Written in standard C with OpenSSL, designed to compile and run on Linux, macOS, and Windows (via WSL).

Project Structure
secure-file-manager/
├── .vault/         # Auto-generated: Stores encrypted files
├── bin/            # Auto-generated: Contains the final executable
├── build/          # Auto-generated: Stores intermediate object files (.o)
├── src/            # Contains all source code (.c) and header files (.h)
│   ├── main.c
│   ├── file_manager.c
│   ├── file_manager.h
│   ├── crypto.c
│   └── crypto.h
└── Makefile        # The build script for compiling the project

Setup and Prerequisites
To collaborate on this project, you need a C compiler (gcc), the make build tool, and the OpenSSL development library installed on your system. Below are detailed instructions for different operating systems.

On Linux (Debian, Ubuntu, Kali Linux)
This is the most straightforward environment. Open your terminal and run the following command to install all necessary packages:

sudo apt update && sudo apt install build-essential libssl-dev git

build-essential: Installs gcc, make, and other critical build tools.

libssl-dev: Provides the header files and libraries for OpenSSL.

On Windows (Recommended: Use WSL)
The best and most reliable way to work on this project on Windows is by using the Windows Subsystem for Linux (WSL). This avoids common issues with setting up a C development environment and managing system paths on Windows.

Install WSL: Follow the official Microsoft guide to install WSL and a Linux distribution like Ubuntu.

Open your WSL terminal (e.g., Ubuntu).

Install Prerequisites: Inside the WSL terminal, run the same command as for Linux:

sudo apt update && sudo apt install build-essential libssl-dev git

Access Your Files: Your Windows drives are automatically available inside WSL under the /mnt/ directory. For example, your E:\ drive can be accessed at /mnt/e/. Navigate to your project folder using a command like:

cd /mnt/e/secure-file-manager

On macOS
Using Homebrew is the recommended package manager for macOS.

Install Homebrew if you don't have it.

Install the required packages in your terminal:

brew install gcc make openssl git

Note: macOS comes with a C compiler (Clang), but installing gcc can sometimes be helpful for compatibility. The system's make is sufficient.

How to Compile
Once the prerequisites are installed, you can compile the project with a single command.

Clone the repository:

git clone <your-repository-url>

Navigate into the project directory:

cd secure-file-manager

Compile the code using the Makefile:

make

This command reads the Makefile and automatically compiles all source files, creating the executable at bin/secure_file_manager.

Troubleshooting Common Issues
make: command not found (on WSL/Linux):
This means the build tools are not installed. Run sudo apt install build-essential.

Errors like openssl/evp.h: No such file or directory:
This means the OpenSSL development library is missing. Run sudo apt install libssl-dev.

Permission Denied errors when copying files from Windows to WSL:
This can happen due to filesystem permission conflicts between Windows and Linux. The best solution is to work with the files inside the WSL filesystem. Copy the project from your Windows drive to your WSL home directory (~/):

# Example copy command
cp -r /mnt/e/secure-file-manager ~/
cd ~/secure-file-manager

Terminal becomes unresponsive in WSL:
If commands like pwd or ls produce no output, your WSL instance may be frozen. Open PowerShell on Windows and run wsl --shutdown to force a restart, then open your WSL terminal again.

How to Run the Program
All commands are run from the project's root directory.

Create a test file first:
echo "This is my top secret data." > secret_note.txt

Vault Commands
Add a file: ./bin/secure_file_manager add secret_note.txt MyStrongPassword123

List files: ./bin/secure_file_manager list

Retrieve a file: ./bin/secure_file_manager retrieve secret_note.txt.enc decrypted_note.txt MyStrongPassword123

Delete a file: ./bin/secure_file_manager delete secret_note.txt.enc MyStrongPassword123

Utility Commands
Hash with SHA-256: ./bin/secure_file_manager hash sha256 secret_note.txt

Hash with SHA-512: ./bin/secure_file_manager hash sha512 secret_note.txt

Directly encrypt: ./bin/secure_file_manager encrypt secret_note.txt manual_encrypted.dat MyStrongPassword123

Directly decrypt: ./bin/secure_file_manager decrypt manual_encrypted.dat manual_decrypted.txt MyStrongPassword123

Conclusion
This tool provides a secure, reliable, and transparent way to manage sensitive files directly from the command line. By leveraging the robust cryptographic primitives offered by OpenSSL, it ensures that data remains confidential and its integrity can be verified. The modular C code is designed to be readable, maintainable, and easily extensible for future features.

References
OpenSSL Cryptography and SSL/TLS Toolkit: https://www.openssl.org/

AES (Advanced Encryption Standard) - Wikipedia: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

PBKDF2 (Password-Based Key Derivation Function 2) - Wikipedia: https://en.wikipedia.org/wiki/PBKDF2
