
# FileEncryptor - Windows Forms PowerShell GUI

## Overview

FileEncryptor is a Windows Forms-based PowerShell GUI tool that enables you to encrypt and decrypt entire folder structures using AES-256 encryption with password-based key derivation (PBKDF2).

## Features

- AES-256 encryption in CBC mode with PKCS7 padding
- Password-based key derivation using PBKDF2 (RFC2898)
- Salt saved alongside encrypted data for safe key regeneration
- Parallel folder browsing and output destination setting
- Secure password handling using `SecureString`
- Real-time status updates
- Simple and familiar Windows Forms UI

## Requirements

- Windows OS
- PowerShell 5.1+

## How to Use

1. Run the `FileEncryptor.ps1` script by right-clicking and selecting "Run with PowerShell".
2. Use the GUI to:
   - Select a source folder.
   - Choose a destination folder.
   - Enter a strong password.
   - Click **Encrypt** or **Decrypt**.
3. Encrypted files will have `.aes` extension added.
4. A `salt.bin` file will be saved in the destination folder — required for decryption.

## Security Note

- Always store the `salt.bin` file securely.
- Without the original salt and password, decryption is not possible.

## License

This script is provided as-is with no warranty. Use at your own risk.
