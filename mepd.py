#!/usr/bin/env python3
"""
Edge Password Decryptor (EPD)
Based on work by rishabh-a7da6 (MIT License)
Enhanced with Zero-Dependency mode and CSV export.
"""

import argparse
import os
import sys
import sqlite3
import csv
import base64
import json
import ctypes
from pathlib import Path
from ctypes import wintypes

# --- Global / Fallback configurations ---
HAS_CRYPTODOME = False
try:
    from Cryptodome.Cipher import AES
    HAS_CRYPTODOME = True
except ImportError:
    try:
        from Crypto.Cipher import AES
        HAS_CRYPTODOME = True
    except ImportError:
        HAS_CRYPTODOME = False

# --- Windows structs for Zero-Dependency mode ---
if not HAS_CRYPTODOME and sys.platform == 'win32':
    class BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD), ("dwInfoVersion", wintypes.DWORD),
            ("pbNonce", ctypes.c_void_p), ("cbNonce", wintypes.DWORD),
            ("pbAuthData", ctypes.c_void_p), ("cbAuthData", wintypes.DWORD),
            ("pbTag", ctypes.c_void_p), ("cbTag", wintypes.DWORD),
            ("pbMacContext", ctypes.c_void_p), ("cbMacContext", wintypes.DWORD),
            ("cbAAD", wintypes.DWORD), ("cbData", ctypes.c_ulonglong),
            ("dwFlags", wintypes.DWORD),
        ]

def get_theme():
    """Detects encoding and returns a UI theme (UTF-8 or ASCII)."""
    encoding = sys.stdout.encoding or 'ascii'
    if 'utf' in encoding.lower():
        return {
            'v': '║', 'h': '═', 'tl': '╔', 'tr': '╗',
            'bl': '╚', 'br': '╝', 'tm': '╦', 'bm': '╩', 'ml': '╠', 'mr': '╣', 'mm': '╬'
        }
    else:
        return {
            'v': '|', 'h': '-', 'tl': '+', 'tr': '+',
            'bl': '+', 'br': '+', 'tm': '+', 'bm': '+', 'ml': '+', 'mr': '+', 'mm': '+'
        }

def get_edge_secret_key(local_state_path):
    """Retrieves and decrypts the Edge master key using Windows DPAPI."""
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def unprotect_data(encrypted_bytes):
        crypt32 = ctypes.windll.crypt32
        blob_in = DATA_BLOB(len(encrypted_bytes), ctypes.create_string_buffer(encrypted_bytes))
        blob_out = DATA_BLOB()
        if crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
            result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return result
        return None

    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        secret_key = unprotect_data(encrypted_key)
        if secret_key:
            print(f"\n[+] DPAPI decrypted secret key: {secret_key.hex()}")
            return secret_key
    except Exception as e:
        print(f"[-] Error retrieving key: {e}")
    return None

def _decrypt_windows_native(ciphertext, secret_key):
    """Fallback decryption using native bcrypt.dll (No dependencies)."""
    try:
        iv, payload, tag = ciphertext[3:15], ciphertext[15:-16], ciphertext[-16:]
        bcrypt = ctypes.windll.bcrypt
        hAlg, hKey = wintypes.HANDLE(), wintypes.HANDLE()
        bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(hAlg), u"AES", None, 0)
        mode = ctypes.create_unicode_buffer(u"ChainingModeGCM")
        bcrypt.BCryptSetProperty(hAlg, u"ChainingMode", mode, ctypes.sizeof(mode), 0)
        key_buffer = ctypes.create_string_buffer(secret_key)
        bcrypt.BCryptGenerateSymmetricKey(hAlg, ctypes.byref(hKey), None, 0, key_buffer, ctypes.sizeof(key_buffer), 0)
        auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
        auth_info.cbSize, auth_info.dwInfoVersion = ctypes.sizeof(auth_info), 1
        auth_info.pbNonce, auth_info.cbNonce = ctypes.cast(ctypes.create_string_buffer(iv), ctypes.c_void_p), len(iv)
        auth_info.pbTag, auth_info.cbTag = ctypes.cast(ctypes.create_string_buffer(tag), ctypes.c_void_p), len(tag)
        plaintext = ctypes.create_string_buffer(len(payload))
        cbPlain = wintypes.DWORD(len(payload))
        status = bcrypt.BCryptDecrypt(hKey, payload, len(payload), ctypes.byref(auth_info), None, 0, plaintext, len(payload), ctypes.byref(cbPlain), 0)
        bcrypt.BCryptDestroyKey(hKey)
        bcrypt.BCryptCloseAlgorithmProvider(hAlg, 0)
        return plaintext.value.decode('utf-8', errors='ignore') if status == 0 else f"[Error {hex(status)}]"
    except Exception as e:
        return f"[Native Error: {e}]"

def decrypt_password(ciphertext, secret_key):
    """Adaptive decryption: Tries Cryptodome, then falls back to Windows Native API."""
    if not ciphertext or ciphertext[:3] != b'v10': return "[Old/Invalid Format]"
    e = None
    if HAS_CRYPTODOME:
        try:
            iv, payload, tag = ciphertext[3:15], ciphertext[15:-16], ciphertext[-16:]
            cipher = AES.new(secret_key, AES.MODE_GCM, iv)
            return cipher.decrypt_and_verify(payload, tag).decode('utf-8', errors='ignore')
        except Exception as err:
            e = err
            pass
    if sys.platform == 'win32':
        return _decrypt_windows_native(ciphertext, secret_key)
    return f"[Error: {e}]" if HAS_CRYPTODOME else "[Missing Cryptodome]"

def decrypt_db(secret, connection, output_file=None):
    """Fetches data from DB and prints/exports results."""
    theme = get_theme()
    fields = ["action_url", "origin_url", "username_value", "password_value"]
    
    try:
        cursor = connection.cursor()
        cursor.execute(f"SELECT {','.join(fields)} FROM logins")
        rows = cursor.fetchall()

        # Terminal UI settings
        try: w = os.get_terminal_size()[0]
        except OSError: w = 120
        pad = (w // len(fields)) - 2

        def print_sep(l, m, r): print(f"{l}{m.join([theme['h']*pad for _ in fields])}{r}")

        print(f"[*] Extracting {len(rows)} entries...")
        
        csv_data = []
        # Header for terminal
        print_sep(theme['tl'], theme['tm'], theme['tr'])
        print(f"{theme['v']}{theme['v'].join([f.center(pad) for f in fields])}{theme['v']}")
        print_sep(theme['ml'], theme['mm'], theme['mr'])

        for idx, row in enumerate(rows):
            decrypted_row = []
            for i, val in enumerate(row):
                if fields[i] == "password_value" and val:
                    val = decrypt_password(val, secret)
                clean_val = str(val).strip() if val else ""
                decrypted_row.append(clean_val)
            
            csv_data.append(decrypted_row)
            
            # Print to terminal with truncation
            term_row = [ (v[:pad-3]+"..." if len(v)>pad else v.ljust(pad)) for v in decrypted_row ]
            print(f"{theme['v']}{theme['v'].join(term_row)}{theme['v']}")
            if idx < len(rows) - 1: print_sep(theme['ml'], theme['mm'], theme['mr'])

        print_sep(theme['bl'], theme['bm'], theme['br'])

        if output_file:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(fields)
                writer.writerows(csv_data)
            print(f"[+] Successfully exported to {output_file}")

    except Exception as e: print(f"[-] DB Error: {e}")
    finally:
        connection.close()
        os.remove("temp.db")

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    
    parser = argparse.ArgumentParser(description="Edge Password Decryptor (EPD)")
    parser.add_argument('-d', '--login-data', type=Path, help='Path to "Login Data" file')
    parser.add_argument('-s', '--local-state', type=Path, help='Path to "Local State" file')
    parser.add_argument('-k', '--secret-key', type=str, help='Decrypted Master Key (HEX)')
    parser.add_argument('-o', '--output', type=str, help='Output CSV file path')
    parser.add_argument('-r', '--retrieve-key', action='store_true', help='Only retrieve the key and exit')

    args = parser.parse_args()
    
    try:
        # 1. Obtain Secret Key
        if args.retrieve_key or not args.secret_key:
            if sys.platform != 'win32':
                print("[!] Key retrieval requires Windows."); exit(1)
            path_ls = args.local_state or os.path.join(os.environ['LOCALAPPDATA'], r"Microsoft\Edge\User Data\Local State")
            secret = get_edge_secret_key(path_ls)
            if args.retrieve_key or not secret: exit(0 if secret else 1)
        else:
            secret = bytes.fromhex(args.secret_key)

        # 2. Process Databases
        if args.login_data:
            import shutil
            shutil.copy2(args.login_data, "temp.db")
            conn = sqlite3.connect("temp.db")
            decrypt_db(secret, conn, args.output)
        else:
            if sys.platform != 'win32': print("[!] Auto-search requires Windows."); exit(1)
            base_path = os.path.join(os.environ['LOCALAPPDATA'], r"Microsoft\Edge\User Data")
            profiles = [d for d in os.listdir(base_path) if d.startswith("Profile") or d == "Default"]
            for p in profiles:
                db_path = os.path.join(base_path, p, 'Login Data')
                if os.path.exists(db_path):
                    print(f"\n[+] Processing profile: {p}")
                    import shutil
                    shutil.copy2(db_path, "temp.db")
                    conn = sqlite3.connect("temp.db")
                    decrypt_db(secret, conn, args.output)

    except Exception as e: print(f"[-] Global Error: {e}")

if __name__ == '__main__': main()
