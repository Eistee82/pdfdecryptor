"""PDF Decryptor — Removes password protection from PDF files."""

import ctypes
import ctypes.wintypes
import glob
import os
import shutil
import sys

import pikepdf

# --- Exit Codes ---

EXIT_OK = 0
EXIT_PASSWORD = 1
EXIT_ERROR = 2

# --- Console Detection ---

CONSOLE_MODE = False


def init_console():
    """Detects whether a console is available. Sets CONSOLE_MODE."""
    global CONSOLE_MODE
    # PyInstaller with --noconsole sets sys.stdout to None
    if sys.stdout is not None:
        CONSOLE_MODE = True
        return
    # No own console — try to attach to parent console (.exe launched from cmd/PowerShell)
    if ctypes.windll.kernel32.AttachConsole(-1):  # ATTACH_PARENT_PROCESS
        sys.stdin = open("CONIN$", "r")
        sys.stdout = open("CONOUT$", "w")
        sys.stderr = open("CONOUT$", "w")
        CONSOLE_MODE = True


# --- Windows Credential Manager ---

CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2
CREDENTIAL_TARGET = "PDFDecryptor"

advapi32 = ctypes.windll.advapi32


class CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
        ("TargetName", ctypes.wintypes.LPWSTR),
        ("Comment", ctypes.wintypes.LPWSTR),
        ("LastWritten", ctypes.wintypes.FILETIME),
        ("CredentialBlobSize", ctypes.wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
        ("Persist", ctypes.wintypes.DWORD),
        ("AttributeCount", ctypes.wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", ctypes.wintypes.LPWSTR),
        ("UserName", ctypes.wintypes.LPWSTR),
    ]


PCREDENTIAL = ctypes.POINTER(CREDENTIAL)


def credential_read():
    """Reads the stored password from the Windows Credential Manager."""
    pcred = PCREDENTIAL()
    if advapi32.CredReadW(CREDENTIAL_TARGET, CRED_TYPE_GENERIC, 0, ctypes.byref(pcred)):
        try:
            cred = pcred.contents
            blob = (ctypes.c_byte * cred.CredentialBlobSize).from_address(
                ctypes.addressof(cred.CredentialBlob.contents)
            )
            return bytes(blob).decode("utf-16-le")
        finally:
            advapi32.CredFree(pcred)
    return None


def credential_write(password):
    """Stores the password in the Windows Credential Manager."""
    encoded = password.encode("utf-16-le")
    blob = (ctypes.c_byte * len(encoded))(*encoded)
    cred = CREDENTIAL()
    cred.Type = CRED_TYPE_GENERIC
    cred.TargetName = CREDENTIAL_TARGET
    cred.CredentialBlobSize = len(encoded)
    cred.CredentialBlob = blob
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE
    cred.UserName = "PDFDecryptor"
    return advapi32.CredWriteW(ctypes.byref(cred), 0)


def credential_delete():
    """Deletes the stored password from the Windows Credential Manager."""
    return advapi32.CredDeleteW(CREDENTIAL_TARGET, CRED_TYPE_GENERIC, 0)


# --- UI Helper Functions (console and GUI capable) ---


def info(text):
    """Displays an info message."""
    if CONSOLE_MODE:
        print(text)
    else:
        ctypes.windll.user32.MessageBoxW(0, text, "PDF Decryptor", 0x40)


def error(text):
    """Displays an error message."""
    if CONSOLE_MODE:
        print(f"ERROR: {text}", file=sys.stderr)
    else:
        ctypes.windll.user32.MessageBoxW(0, text, "PDF Decryptor", 0x10)


def ask_yesno(text):
    """Yes/No question. Returns True for Yes."""
    if CONSOLE_MODE:
        answer = input(f"{text} (y/n): ").strip().lower()
        return answer in ("y", "yes")
    result = ctypes.windll.user32.MessageBoxW(0, text, "PDF Decryptor", 0x24)
    return result == 6  # IDYES


def ask_yesnocancel(text):
    """Yes/No/Cancel question. Returns 'yes', 'no' or 'cancel'."""
    if CONSOLE_MODE:
        answer = input(f"{text} (y/n/c): ").strip().lower()
        if answer in ("y", "yes"):
            return "yes"
        if answer in ("n", "no"):
            return "no"
        return "cancel"
    result = ctypes.windll.user32.MessageBoxW(0, text, "PDF Decryptor", 0x23)
    if result == 6:
        return "yes"
    if result == 7:
        return "no"
    return "cancel"


def prompt_password():
    """Prompts the user for a password."""
    if CONSOLE_MODE:
        import getpass
        return getpass.getpass("Enter PDF password: ").strip()

    import tkinter as tk

    result = []

    win = tk.Tk()
    win.title("PDF Decryptor")
    win.resizable(False, False)

    tk.Label(win, text="Enter PDF password:").pack(padx=20, pady=(15, 5))
    entry = tk.Entry(win, show="*", width=35)
    entry.pack(padx=20, pady=5)

    def submit(event=None):
        result.append(entry.get().strip())
        win.destroy()

    entry.bind("<Return>", submit)
    tk.Button(win, text="OK", command=submit, width=10).pack(pady=(5, 15))

    entry.focus_set()
    win.update_idletasks()
    x = (win.winfo_screenwidth() - win.winfo_reqwidth()) // 2
    y = (win.winfo_screenheight() - win.winfo_reqheight()) // 2
    win.geometry(f"+{x}+{y}")

    win.mainloop()
    return result[0] if result else ""


def choose_file():
    """Opens a file chooser dialog and returns the selected path."""
    if CONSOLE_MODE:
        return None  # In console mode the path must be passed as an argument

    import tkinter as tk
    from tkinter import filedialog

    root = tk.Tk()
    root.withdraw()
    path = filedialog.askopenfilename(
        title="Select PDF file",
        filetypes=[("PDF files", "*.pdf")],
    )
    root.destroy()
    return path


# --- Password Management ---


def manage_password():
    """Offers the user to change or delete the stored password."""
    existing = credential_read()
    if existing:
        result = ask_yesnocancel(
            "A password is stored.\n\n"
            "Yes = Set new password\n"
            "No = Delete password"
        )
        if result == "yes":
            password = prompt_password()
            if password:
                credential_write(password)
                info("New password saved.")
        elif result == "no":
            credential_delete()
            info("Password deleted.")
    else:
        if ask_yesno("No password stored.\n\nWould you like to set one now?"):
            password = prompt_password()
            if password:
                credential_write(password)
                info("Password saved.")


# --- Command Helpers ---


def parse_args():
    """Parses command-line arguments. Returns (command, value, flags, paths)."""
    command = None
    command_value = None
    flags = set()
    paths = []

    for arg in sys.argv[1:]:
        arg_lower = arg.lower()
        if arg_lower in ("/set", "/setpassword"):
            command = "set"
        elif arg_lower.startswith("/p:") or arg_lower.startswith("/password:"):
            command = "use"
            command_value = arg.split(":", 1)[1]
        elif arg_lower in ("/delete", "/clear"):
            command = "delete"
        elif arg_lower in ("/help", "/?"):
            command = "help"
        elif arg_lower in ("/backup", "/bak"):
            flags.add("backup")
        else:
            paths.append(arg)

    return command, command_value, flags, paths


def collect_pdfs(paths):
    """Collects PDF files from paths. Directories are searched for PDFs."""
    pdf_paths = []
    for path in paths:
        if os.path.isdir(path):
            pdf_paths.extend(sorted(glob.glob(os.path.join(path, "*.pdf"))))
        else:
            pdf_paths.append(path)
    return pdf_paths


def show_help():
    """Displays the help text."""
    text = (
        "Usage:\n\n"
        "  pdfdecryptor.exe [options] [PDF/folder]\n\n"
        "Options:\n"
        "  /set                Set and save a new password\n"
        "  /p:PASSWORD     Use password once (without saving)\n"
        "  /delete             Delete stored password\n"
        "  /backup            Create backup (.bak) before decryption\n"
        "  /help                Show this help\n\n"
        "Without options:\n"
        "  Drag a PDF or folder onto the .exe.\n"
        "  Folder: all PDFs inside will be decrypted.\n\n"
        "Exit codes:\n"
        "  0 = Success\n"
        "  1 = Wrong password\n"
        "  2 = Error (file not found, save error, etc.)"
    )
    if CONSOLE_MODE:
        print(text)
    else:
        info(text)


def fix_hidden_attr(path):
    """Removes the hidden attribute if set."""
    attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
    if attrs != -1 and attrs & 2:  # FILE_ATTRIBUTE_HIDDEN
        ctypes.windll.kernel32.SetFileAttributesW(path, attrs & ~2)


def decrypt_pdf(pdf_path, password, backup=False):
    """Decrypts a PDF file. Returns True on success, False on error, None on wrong password."""
    if not os.path.isfile(pdf_path):
        error(f"File not found:\n{pdf_path}")
        return False

    try:
        pdf = pikepdf.open(pdf_path, password=password, allow_overwriting_input=True)
    except pikepdf.PasswordError:
        try:
            pdf = pikepdf.open(pdf_path)
            pdf.close()
            info(f"This PDF is not password-protected:\n{os.path.basename(pdf_path)}")
            return False
        except pikepdf.PasswordError:
            return None
    except Exception as e:
        error(f"Error opening PDF:\n{e}")
        return False

    try:
        if backup:
            shutil.copy2(pdf_path, pdf_path + ".bak")
        pdf.save(pdf_path)
        fix_hidden_attr(pdf_path)
        if CONSOLE_MODE:
            print(f"OK: {os.path.basename(pdf_path)}")
        return True
    except Exception as e:
        error(f"Error saving PDF:\n{e}")
        return False
    finally:
        pdf.close()


def decrypt_with_retry(pdf_paths, password, backup=False):
    """Decrypts PDFs. Offers retry on wrong password in GUI mode.

    Returns the highest exit code (EXIT_OK, EXIT_PASSWORD, EXIT_ERROR).
    """
    worst = EXIT_OK
    for path in pdf_paths:
        current_pw = password
        while True:
            result = decrypt_pdf(path, current_pw, backup)
            if result is None:
                worst = max(worst, EXIT_PASSWORD)
                if CONSOLE_MODE:
                    error(f"Wrong password for: {os.path.basename(path)}")
                    break
                if ask_yesno(
                    f"Wrong password for:\n{os.path.basename(path)}\n\n"
                    "Try a different password?"
                ):
                    current_pw = prompt_password()
                    if not current_pw:
                        break
                else:
                    break
            elif result is False:
                worst = max(worst, EXIT_ERROR)
                break
            else:
                break
    return worst


# --- Main Logic ---


def main():
    init_console()
    command, command_value, flags, paths = parse_args()
    backup = "backup" in flags

    if command == "help":
        show_help()
        return EXIT_OK

    if command == "set":
        password = prompt_password()
        if password:
            credential_write(password)
            info("Password saved.")
        return EXIT_OK

    if command == "delete":
        if credential_read():
            credential_delete()
            info("Password deleted.")
        else:
            info("No password stored.")
        return EXIT_OK

    if command == "use":
        password = command_value
    else:
        password = credential_read()

    if not password:
        password = prompt_password()
        if not password:
            return EXIT_OK
        if ask_yesno("Save password for future use?"):
            credential_write(password)

    pdf_paths = collect_pdfs(paths)

    if not pdf_paths:
        pdf_path = choose_file()
        if not pdf_path:
            if CONSOLE_MODE:
                info("No PDF file specified. Usage: pdfdecryptor.exe [PDF/folder]")
            else:
                manage_password()
            return EXIT_OK
        pdf_paths = [pdf_path]

    return decrypt_with_retry(pdf_paths, password, backup)


if __name__ == "__main__":
    sys.exit(main())
