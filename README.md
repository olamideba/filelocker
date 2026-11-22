# FileLocker

Lock files and folders on Windows 10 and Windows 11 with a PIN or password. Right-click, lock, done.

- **Open FileLocker → Lock a file… / Lock a folder…**, or right-click any file or folder → **Lock with FileLocker**.
- **Double-click a locked file** → type your PIN → it opens.
- **Padlock icon** on locked files and folders.
- **Real encryption** (AES-256). Files are encrypted *in place*: no copies, no zip files, no extra disk space.
- **Fast and light.** About 1 MB installed, starts instantly, fine on an Intel Core i3.
- **Free and open source** (MIT).

## Install

1. Go to [Releases](https://github.com/olamideba/filelocker/releases/latest) and download **FileLocker-Setup.exe**.
2. Run it. If Windows says *"Windows protected your PC"*, click **More info → Run anyway**. The app isn't code-signed yet, so Windows doesn't recognise the publisher.
3. No administrator password is needed. It installs for the current Windows user.
4. At the end, leave **"Set up FileLocker now"** ticked. Choose a **PIN** (6+ digits) or a **password** (8+ characters).
5. **Save your recovery key.** Write it down or save it somewhere off this PC. If you forget your PIN, it's the only way back in.

Needs Windows 10 (version 1803 or newer) or Windows 11. Nothing else to install.

## Use

Open **FileLocker** from the Start menu. It lists everything you've locked: **Locked**, **Open** (unlocked for now) or **Can't find it** (moved or deleted).

| To… | Do this |
| --- | --- |
| Lock a file or folder | In FileLocker: **Lock a file…** / **Lock a folder…**. Or right-click it → **Lock with FileLocker** |
| Open something locked | Double-click it (in FileLocker or in your folders), then type your PIN |
| Lock it again when you're done | Nothing to do: **close the program** (or the folder window) and it locks itself again a few seconds later. To lock right away: FileLocker → **Lock everything now** |
| Open a whole folder | Right-click it → **Unlock and open folder**, or double-click it in FileLocker. It locks again when you close the folder window |
| Unlock without auto-locking | Right-click a locked file → **Unlock and keep unlocked**. It stays open until you lock it again |
| **Remove a lock for good** | In FileLocker: select it → **Remove lock…** → type your PIN. Only possible from the app, and the PIN is always asked for, even if you typed it a minute ago |
| Change your PIN | FileLocker → *Change PIN or password* |
| Forgot your PIN | FileLocker → *Forgot PIN?*, or double-click a locked file → *Forgot it? Use your recovery key* |

**On Windows 11** the FileLocker entries sit under **"Show more options"** in the right-click menu. Holding **Shift** while right-clicking opens that full menu directly.

FileLocker asks for your PIN **every time** something locked is opened. It never remembers it. A PIN is exactly 6 digits, typed into 6 boxes; it checks automatically when the 6th digit is in.

**How "locks again when closed" works:** a small background part of FileLocker checks every 2 seconds whether the file is still in use: is the program that opened it still running, does a program still hold the file, does a window title still show its name, and (for folders) is an Explorer window still showing it. After about 6 seconds of nothing using it, it's locked again. It also runs when you sign in, to finish anything left open at shutdown. Some apps don't show the file name or hold the file; for those it may lock again while the app is still on screen, which is harmless because the app already has what it loaded.

Selecting many files and choosing *Lock* (or *Unlock*) handles them together in one window, with one PIN prompt.

## Updating

FileLocker → **Check for updates**. If there's a new version it downloads and installs it for you. Or download the newest `FileLocker-Setup.exe` from Releases and run it over the old one.

Either way, your PIN, recovery key, list and locked files stay exactly as they are. Nothing needs uninstalling first.

## What "locked" means

- A locked file is renamed `name.ext.locked` and its contents are AES-256 encrypted. Other programs can't open it, and neither can someone who copies it to a USB stick or removes the hard drive.
- In a locked folder, every file inside is locked and the folder shows a padlock. You can still browse a locked folder and see the file **names**. Their **contents** need the PIN.
- Things you open **lock themselves again when you close them.** *Lock everything now* locks everything immediately.

## Good to know

- **Files that are open in another program can't be locked.** Close them first. FileLocker tells you which ones it skipped.
- **Don't lose both your PIN and your recovery key.** Without one of them, nobody can recover the files. That's the point of encryption.
- **Keys are per computer.** Files locked on one PC can only be unlocked on that PC (your key lives in `%APPDATA%\FileLocker`). Back up that folder together with your recovery key if you want to be safe.
- **Uninstalling doesn't unlock anything.** Unlock what you need first. Reinstalling on the same PC (same Windows user) unlocks them again.
- System folders, whole drives and your main user folders (Desktop, Documents, etc. as a whole) can't be locked, so you can't break Windows by accident. Folders *inside* them are fine.
- Windows Defender's *Controlled folder access* (off by default) may block FileLocker from changing files in Documents/Desktop. If you see "access denied", allow FileLocker in Windows Security → Ransomware protection.

## How it works (for the curious)

- At setup a 2048-bit RSA key pair is created. The **public** key is stored as-is, which is why locking never asks for your PIN. The **private** key is stored encrypted twice: once with a key derived from your PIN/password (PBKDF2-SHA256, 200,000 rounds) and once with a key derived from the recovery key.
- Each file gets its own random AES-256 key. Its bytes are overwritten with AES-256-CTR ciphertext (same length), and a 512-byte trailer is appended holding the file key (RSA-OAEP encrypted) and the original length.
- The trailer records how far encryption has got. If the PC loses power mid-lock or mid-unlock, unlocking still restores the file.
- The folder padlock is a standard `desktop.ini` icon.

Built with C# on .NET Framework 4.7.2 (WinForms) and Inno Setup. Every push is built and tested on a real Windows machine by GitHub Actions.

## Build it yourself

```powershell
dotnet build src/FileLocker -c Release -o out           # the app
dotnet build tests/FileLocker.Tests -c Release -o testbin
./testbin/FileLocker.Tests.exe                           # the tests
iscc installer/FileLocker.iss                            # the installer (Inno Setup 6)
```

## License

MIT
