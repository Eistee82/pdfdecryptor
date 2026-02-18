# PDF Decryptor

Windows tool for removing password protection from PDF files. Via drag-and-drop or file chooser dialog.

## Download

Download `pdfdecryptor.exe` from the [Releases page](../../releases).

## Usage

1. Drag a password-protected PDF file onto `pdfdecryptor.exe`
2. On first use you will be prompted for the password — with the option to save it
3. The PDF is decrypted and the original is overwritten

Alternatively: double-click `pdfdecryptor.exe` — a file chooser dialog will open.

The password is stored encrypted in the Windows Credential Manager.

### Command-Line Options

| Command | Description |
|---|---|
| `/set` | Set and save a new password |
| `/p:PASSWORD` | Use password once (without saving) |
| `/delete` | Delete stored password |
| `/backup` | Create backup (.bak) before decryption |
| `/help` | Show help |

Examples:
```
pdfdecryptor.exe /set
pdfdecryptor.exe /p:MyPassword file.pdf
pdfdecryptor.exe /backup file.pdf
pdfdecryptor.exe /delete
```

You can also drag **folders** onto the .exe — all PDFs inside will be decrypted.

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Wrong password |
| `2` | Error (file not found, save error, etc.) |

Scripting example:
```bat
pdfdecryptor.exe /p:MyPassword file.pdf
if %errorlevel% equ 1 echo Wrong password!
if %errorlevel% equ 2 echo Error occurred!
```

### Password Management

Alternatively: launch `pdfdecryptor.exe` and click **Cancel** in the file chooser dialog — you will be offered the option to change or delete the stored password.

## Messages

| Situation | Message |
|---|---|
| Success | None — app simply closes |
| PDF not encrypted | "This PDF is not password-protected" |
| Wrong password | Retry dialog: try a different password |

## Building

Requires: Python 3 with pip.

```
build.bat
```

Automatically installs dependencies (pikepdf, PyInstaller) and creates `release/pdfdecryptor.exe`.

## Notice

This tool is intended solely for your own, lawfully acquired PDF files. Using it to circumvent protection measures on copyrighted works belonging to others may violate applicable law.

## Third-Party

This project uses [pikepdf](https://github.com/pikepdf/pikepdf) (MPL-2.0).

## License

MIT
