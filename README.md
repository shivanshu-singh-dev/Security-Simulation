# Terminal Security Simulator

A terminal-based security simulation project developed as a semester project. It models secure user session management, access control lists (ACL), multi-factor authentication (MFA), audit logging, and file encryption/decryption.

## Features

- **User Authentication & Role Management**: Models Admin, User, and Guest roles with registration and login logic. Protects against basic brute-force attempts by locking accounts after 5 consecutive failed logins.
- **Access Control Lists (ACL)**: Restricts file read, write, execution, deletion, and creation based on user roles and specific permissions (e.g. system logs are restricted to superusers).
- **Multi-Factor Authentication (MFA)**: Generates temporary 6-digit MFA codes for Admin logins, valid for 120 seconds.
- **Session Lifecycle & Auto-Logout**: Manages active login session tokens. Implements a thread-based auto-logout timeout mechanism.
- **File Encryption / Decryption**: Standard AES-256-CBC encryption (utilizing custom cryptographic routines with PKCS#7 padding) to secure directories and sensitive files.
- **Continuous Audit Log**: Tracks all user activities and authentication events, storing logs in encrypted files when inactive.

## Build and Run

### Prerequisites

- A C compiler (e.g., `gcc` / MinGW)
- `make` utility (e.g., `mingw32-make` or `make`)

### Steps

1. **Build the project**:
   ```bash
   make
   ```
   or
   ```bash
   mingw32-make
   ```

2. **Run the executable**:
   ```bash
   ./run
   ```

3. **Clean build files**:
   ```bash
   make clean
   ```
