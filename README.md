# pyvmx-cracker

Based on the [VMwareVMX](https://github.com/RF3/VMwareVMX) module, this tool aims to crack VMX encryption passwords. This tool crack the password by successfully decrypting the *dict* structure. If you want to fully decrypt the VMX structure, check the [VMwareVMX](https://github.com/RF3/VMwareVMX) module.

## Description

The VMX files (.vmx) contains the virtual machine informations, VMware VMX configuration files are encrypted when the virtual machine is
encrypted. Here is a sample from an encrypted VMX file :

```bash
.encoding = "UTF-8"
displayName = "Encrypted"
encryption.keySafe = "vmware:key/list/(pair/(phrase/MA3fCocdhNc%3d/pass2key%3dPBKDF2%2dHMAC%2dSHA%2d1%3a
cipher%3dAES%2d256%3arounds%3d1000%3asalt%3d9kxr%2bxeqo4xPz9ttPZUVFA%253d%253d,
HMAC%2dSHA%2d1,X4sG4nJc0yeWAaSkBllAPI4nCrbO2RUE8dXHa82I4KmfNO7JjruuCrWgRRT6EUQHGQP%2bTDjPFSLHZ
s%2bwRpFZXpjyWvJkzwFhx7UJGQriz3SCXWlwrz1zNPYAmqSXiusyFiY4js0CdabNfdFQKtLy79jDuP0%3d))"
encryption.data = "..."
```

The KeyStore is a simple structure, and it contains the information needed by the machine to verify the password each time the user wants to start a machine or change its password. Here are some information about the *KeySafe* structure :

| Name | Description |
| ---- | ----------- | 
| id | Identifier must be 8 bytes long and is just a random number | 
| password_hash | Only PBKDF2-HMAC-SHA-1 algorithm for the password is supported | 
| password_cipher | Only AES-256 encryption algorithm for the dictionary is supported | 
| hash_round | Hash rounds | 
| salt | The salt parameter is used with the password for the PBKDF2-HMAC-SHA-1 | 
| config_hash | Only HMAC-SHA-1 hash algorithm for the configuration is supported | 
| dict | Dictionary (starts with 'type=key:cipher=AES-256:key=' when successfully decrypted) | 
| iv | The IV determined from the decryption process |
| key  | The key from 'dict' once decrypted |
| password | The password identified from a successful decryption |

## Requirements

This tool requires, and installs with, the [pyCrypto](https://www.dlitz.net/software/pycrypto/) module.


## Install

Checkout the source: `git clone https://github.com/digitalsleuth/pyvmx-cracker.git`

## Getting Started

```bash
$ pyvmx-cracker
usage: pyvmx-cracker [-h] -x VMX -w WORDLIST [-d] [-s] [-v]

Simple tool to crack VMware VMX encryption passwords - v1.0

optional arguments:
  -h, --help            show this help message and exit
  -x VMX, --vmx VMX     .vmx file
  -w WORDLIST, --wordlist WORDLIST
                        password list
  -d, --decode          decode encryption.data content
  -s, --silent          display only basic info while cracking, no progress count
  -v, --version         show program's version number and exit


$ pyvmx-cracker -x sample.vmx -w wordlist.txt -d

Starting pyvmx-cracker...

[*] KeySafe information...
        ID = 300ddf0a871d84d7
        Hash = PBKDF2-HMAC-SHA-1
        Algorithm = AES-256
        Config Hash = HMAC-SHA-1
        Salt = f64c6bfb17aaa38c4fcfdb6d3d951514
        Rounds = 10000
        IV = ce7d6470b128998a4a019632ac55438b

[*] Starting bruteforce...
        20 passwords tested...
        40 passwords tested...
        60 passwords tested...
        80 passwords tested...
        100 passwords tested...
        120 passwords tested...
        140 passwords tested...
        160 passwords tested...
        180 passwords tested...
        200 passwords tested...

[*] 211 passwords tested

[*] Password Found = Password123

[*] Decrypted data:
config.version = "8"
virtualHW.version = "19"
mks.enable3d = "TRUE"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
---snip---
```

## Resources

Here are some interesting resources about this project :

- https://github.com/RF3/VMwareVMX

## License

This project is released under the MIT License. See LICENCE file.
