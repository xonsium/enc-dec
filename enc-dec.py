from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import os
from hashlib import sha1
import argparse

# all arguments
arg_parser = argparse.ArgumentParser(prog='Enc-Dec', usage='%(prog)s [options]')
arg_parser.add_argument('-f', '--file', type=str, help='File name', required=True, metavar='')
arg_parser.add_argument('-r', '--rename', type=bool, help='Rename the file', default=False, metavar='')
arg_parser.add_argument('-d', '--delete', type=bool, help='Delete unencrypted file', default=False, metavar='')
arg_parser.add_argument('-a', '--action', type=str, help='enc or dec', required=True, metavar='')

args = arg_parser.parse_args()
file_name = args.file


def key_func():
    # creates key for encryption or takes key for decryption.
    pw = getpass.getpass("enter key: ")
    # makes the string readable for fernet.
    password = pw.encode()
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    # ctrl+v
    return key


def encrypt(key):
    fernet = Fernet(key)
    file, ext = os.path.splitext(file_name)
    file = file.split('\\' or '/')[-1]

    if args.rename:
        encrypted_name = sha1(file_name.encode()).hexdigest() + ext
    else:
        encrypted_name = file + '(enc)' + ext
    with open(file_name, 'rb') as file:
        original = file.read()

    encrypted = fernet.encrypt(original)

    # deletes the unencrypted file if --delete/-d is True.(default=False)
    if args.delete:
        os.remove(file_name)
    else:
        pass

    with open(encrypted_name, 'wb') as file:
        file.write(encrypted)


def decrypt(key):
    fernet = Fernet(key)
    file, ext = os.path.splitext(file_name)
    file = file.split('\\' or '/')[-1]

    if args.rename:
        decrypted_name = sha1(file_name.encode()).hexdigest() + ext
    else:
        decrypted_name = file_name + '(dec)' + ext

    with open(file_name, 'rb') as file:
        encrypted_file = file.read()

    decrypted = fernet.decrypt(encrypted_file)

    # deletes the encrypted file if --delete/-d is True.(default=False)
    if args.delete:
        os.remove(file_name)
    else:
        pass

    with open(decrypted_name, 'wb') as file:
        file.write(decrypted)


if __name__ == "__main__":
    key_pass = key_func()
    if args.action == 'enc':
        encrypt(key_pass)
    elif args.action == 'dec':
        decrypt(key_pass)

