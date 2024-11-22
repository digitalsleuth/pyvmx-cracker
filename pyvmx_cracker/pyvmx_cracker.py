#!/usr/bin/python3

"""
pyvmx-cracker.py: Simple tool to crack VMX encryption passwords

Part of the code was adopted from https://github.com/XMCyber/VmwarePasswordDecryptor
No license currently exists in the above repo.

Chunk reader adapted from Mohammad Hossein Mojtahedi - https://gist.github.com/MHM5000/4d1db2f28b2765149abf95a8331d9df4

"""

__author__ = "axcheron, digitalsleuth"
__license__ = "MIT License"
__version__ = "2.0"

import argparse
import hashlib
import sys
import re
from base64 import b64decode
from urllib.parse import unquote
from binascii import hexlify
from Crypto.Cipher import AES


AES_IV_SIZE = AES.block_size
AES_128_KEY_SIZE = 128 // 8
AES_256_KEY_SIZE = 256 // 8
IDENTIFIER_SIZE = 8
SALT_SIZE = 8
__AES_MODE = AES.MODE_CBC
__HASH_SIZE = 20
__DICT_SIZE = AES_IV_SIZE + 64 + __HASH_SIZE

KEYSAFE_RE = '.+phrase/(.*?)/pass2key=(.*?):cipher=(.*?):rounds=(.*?):salt=(.*?),(.*?),(.*?)\)'
BASE64_RE = '([a-zA-Z0-9\+/=\/]+)'
DATA_RE = '.*\"' + BASE64_RE + '\"'

KS_STRUCT = {
    "id": None,
    "password_hash": None,
    "password_cipher": None,
    "hash_round": None,
    "salt": None,
    "config_hash": None,
    "dict": None,
    "iv": None,
    "key": None,
    "password": None,
}


def print_ksdata(keysafe):
    print("[*] KeySafe information...")
    print(f"\tID = {keysafe['id']}")
    print(f"\tHash = {keysafe['password_hash']}")
    print(f"\tAlgorithm = {keysafe['password_cipher']}")
    print(f"\tConfig Hash = {keysafe['config_hash']}")
    print(f"\tSalt = {hexlify(keysafe['salt']).decode()}")
    print(f"\tIV = {hexlify(keysafe['dict'][:AES.block_size]).decode()}")
    print(f"\tRounds = {keysafe['hash_round']}")


def crack_keysafe(keysafe, words, chunk_size, silent=False):
    print("\n[*] Starting bruteforce...\n")
    keysafe, success, count = read_chunks(words, keysafe, silent, chunk_size, callback=aes_decrypt_keysafe)
    return keysafe, success, count


def aes_decrypt_keysafe(line, eof, wordlist, keysafe, count, silent=False):
    dict_dec = None
    success = False
    if not eof:
        dict_key = hashlib.pbkdf2_hmac(
            "sha1", line.rstrip().encode(), keysafe["salt"], keysafe["hash_round"], 32
        )
        dict_aes_iv = keysafe["dict"][:AES.block_size]
        cipher = AES.new(dict_key, AES.MODE_CBC, dict_aes_iv)
        dict_dec = cipher.decrypt(keysafe["dict"][AES.block_size:-20])

        if count % 20 == 0 and count != 0:
            if not silent:
                print(f"\r\t[-] {count} passwords tested...", end='')
        count += 1
        try:
            if "type=key:cipher=" in dict_dec.decode():
                key = dict_dec.decode().split(":")[-1].split("key=")[-1]
                keysafe["key"] = key
                keysafe["password"] = line.rstrip()
                success = True
                return keysafe, success, count
        except UnicodeDecodeError:
            pass
    else:
         # end of file reached
        print("\n\n[!] End of wordlist")
    return keysafe, success, count

def parse_keysafe(file):
    keysafe = None
    try:
        with open(file, "r", encoding="utf-8") as data:
            lines = data.readlines()
    except (OSError, IOError):
        sys.exit(f"[!] Cannot read from file {data}")

    for line in lines:
        if "encryption.keySafe" in line:
            keysafe = line

    keysafe = unquote(keysafe)

    match = re.match(KEYSAFE_RE, keysafe)
    if not match:
        raise ValueError(
            f"[!] Unsupported format of the encryption.keySafe line:\n{keysafe}"
        )
    vmx_ks = KS_STRUCT

    vmx_ks["id"] = hexlify(b64decode(match.group(1))).decode()
    vmx_ks["password_hash"] = match.group(2)
    vmx_ks["password_cipher"] = match.group(3)
    vmx_ks["hash_round"] = int(match.group(4))
    vmx_ks["salt"] = b64decode(unquote(match.group(5)))
    vmx_ks["config_hash"] = match.group(6)
    vmx_ks["dict"] = b64decode(match.group(7))
    vmx_ks["iv"] = hexlify(b64decode(match.group(7))[:AES.block_size]).decode()

    return vmx_ks


def parse_data(file, key):
    data_line = None
    try:
        with open(file, "r", encoding="utf-8") as vmx:
            lines = vmx.readlines()

    except (OSError, IOError):
        sys.exit(f"[!] Cannot read from file {file}")

    for line in lines:
        if "encryption.data" in line:
            data_line = line

    data_line = unquote(data_line)

    match = re.match(DATA_RE, data_line)
    if not match:
        raise ValueError(
            f"The encryption.data line in the VMX file is in an unidentified format:\n {data_line}"
        )
    data = match.group(1)
    if "%3d" in data:
        data = data.replace("%3d", "=")
    match = re.match(BASE64_RE, data)
    if not match:
        raise ValueError(
            f"The encryption.data line in the VMX file is in an unidentified format:\n {data_line}"
        )
    key = unquote(key)
    if "%3d" in key:
        key = key.replace("%3d", "=")
    b_key = bytes(b64decode(key))
    b_data = bytes(b64decode(data))

    decrypted_data = aes_decrypt_data(b_data, b_key)

    return decrypted_data


def check_files(vmx, wordlist):
    keysafe = None
    try:
        with open(vmx, "r", encoding="utf-8") as data:
            lines = data.readlines()
    except (OSError, IOError):
        sys.exit(f"[!] Cannot read from file {vmx}")

    for line in lines:
        if "encryption.keySafe" not in line:
            pass
        else:
            keysafe = line
    if not keysafe:
        sys.exit("[!] Invalid VMX file or the VMX does not contain encryption data")

    try:
        open(wordlist, "r", encoding="utf-8")
    except IOError:
        print(f"[!] Cannot open wordlist ({wordlist})")
        sys.exit(1)


def aes_decrypt_data(enc: bytes, key: bytes):
    """
    Decrypt using AES algorithm
    :param enc: encrypted data
    :param key: secret key
    :return: decrypted data
    """
    dict_aes_iv = enc[:AES_IV_SIZE]
    cipher = AES.new(key, __AES_MODE, dict_aes_iv)
    dict_dec = cipher.decrypt(enc[AES_IV_SIZE:-__HASH_SIZE])
    del cipher
    # Get the last byte which contains the padding size
    # Layout of dict_dec: Decrypted Dictionary | Padding Bytes | Padding Size (1 byte)
    try:
        padding_size = dict_dec[-1]
    except TypeError:
        sys.exit(1)
    # Check the padding size
    if padding_size < 1 or padding_size > 16:
        msg = f"Illegal dictionary padding value found: {padding_size}".format(
            padding_size
        )
        raise ValueError(msg)
    # Remove all padding bytes (between 1 and 16)
    dict_dec = dict_dec[:-padding_size]
    try:
        return dict_dec.decode("utf-8")
    except UnicodeDecodeError:
        return dict_dec


def read_chunks(wordlist, keysafe, silent, chunk_size, callback):
    """
    read file line by line regardless of its size
    :param wordlist: absolute path of file to read
    :param keysafe: the keysafe dict parsed from the vmx file
    :param silent: boolean, determines whether or not password test count is output to screen
    :param chunk_size: size of data to be read at at time
    :param callback: callback method
    :return: final keysafe, boolean success (password found), count of passwords tested
    """

    def read_in_chunks(file_obj, chunk_size=10000):
        """
        https://stackoverflow.com/a/519653/5130720
        Lazy function to read a file
        Default chunk size: 5000.
        """
        while True:
            data = file_obj.read(chunk_size)
            if not data:
                break
            yield data
    try:
        fp = open(wordlist, 'r')
        data_left_over = None
        count = 0
        # loop through characters
        for chunk in read_in_chunks(fp):


            # if uncompleted data exists
            if data_left_over:
                # print('\n left over found')
                current_chunk = data_left_over + chunk
            else:
                current_chunk = chunk

            # split chunk by new line
            lines = current_chunk.splitlines()

            # check if line is complete
            if current_chunk.endswith('\n'):
                data_left_over = None

            else:
                data_left_over = lines.pop()

            for line in lines:
                keysafe, success, count = callback(line=line, eof=False, keysafe=keysafe, count=count, wordlist=wordlist, silent=silent)
                if success:
                    return keysafe, success, count
                #count += 1
                pass

        if data_left_over:

            current_chunk = data_left_over
            if current_chunk is not None:

                lines = current_chunk.splitlines()

                for line in lines:
                    keysafe, success, count = callback(line=line, eof=False, keysafe=keysafe, count=count, wordlist=wordlist, silent=silent)
                    if success:
                        return keysafe, success, count
                    #count += 1
                    pass

        keysafe, success, count = callback(line=None, eof=True, keysafe=keysafe, count=count, wordlist=wordlist, silent=silent)
        return keysafe, success, count
    except KeyboardInterrupt:
        print("\n\n[!] Aborting...\n")
        sys.exit(130)


def main():
    parser = argparse.ArgumentParser(
        description=f"Simple tool to crack VMware VMX encryption passwords - v{__version__}"
    )

    # Add arguments
    parser.add_argument(
        "-x",
        "--vmx",
        dest="vmx",
        action="store",
        help=".vmx file",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        dest="wordlist",
        action="store",
        help="password list",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-c",
        "--chunk-size",
        dest="chunk",
        action="store",
        help="for large wordlists, no. of lines to read in chunks: default=100000",
        type=int,
        default=100000,
    )
    parser.add_argument(
        "-d",
        "--decode",
        dest="decode",
        action="store_true",
        help="decode encryption.data content",
    )
    parser.add_argument(
        "-s",
        "--silent",
        dest="silent",
        action="store_true",
        help="display only basic info while cracking, no progress count",
        default=False,
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    if args.vmx and args.wordlist:
        print("\n[*] Starting pyvmx-cracker...\n")
        decrypted_data = None
        # Some validation...
        check_files(args.vmx, args.wordlist)
        # Map KeyStore to Dict
        parsed_ks = parse_keysafe(args.vmx)
        # Print info
        print_ksdata(parsed_ks)
        # Crack keysafe
        results, success, count = crack_keysafe(parsed_ks, args.wordlist, args.chunk, args.silent)
        if success:
            print(f"\n\n[*] Password Found = {results['password']}")
            print(f"[*] {count} passwords tested\n")
        else:
            print(f"[!] Tested {count} passwords - no matching password found\n")
            sys.exit(0)
        if args.decode:
            decrypted_data = parse_data(args.vmx, results["key"])
        if decrypted_data:
            print(f"\n[*] Decrypted data:\n{decrypted_data}")

#        pyvmx(args.vmx, args.wordlist, args.silent, args.decode)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
