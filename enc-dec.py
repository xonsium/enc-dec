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
arg_parser = argparse.ArgumentParser(prog='Enc', usage='%(prog)s [options] path')
arg_parser.add_argument('-p', '--path', type=str, help='Path to all files', required=True, metavar='')
arg_parser.add_argument('-r', '--rename', type=bool, help='Rename all the files', default=True, metavar='')
arg_parser.add_argument('-d', '--delete', type=bool, help='Deletes unencrypted files', default=True, metavar='')
arg_parser.add_argument('-a', '--action', type=str, help='enc or dec', required=True, metavar='')

args = arg_parser.parse_args()


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


def change_path():
    # changes path to the --path argument.
    path = args.path
    os.chdir(path=path)


def rename():
    # renames all files if --rename/-r is True.(default=True)
    for file_name in os.listdir():
        ext = os.path.splitext(file_name)[1]
        new_name = sha1(file_name.encode()).hexdigest() + ext
        os.rename(file_name, new_name)


def encrypt(key):
    fernet = Fernet(key)
    for file_name in os.listdir():
        ext = os.path.splitext(file_name)[1]
        if args.rename:
            encrypted_name = sha1(file_name.encode()).hexdigest() + ext
        else:
            encrypted_name = file_name
        with open(file_name, 'rb') as file:
            original = file.read()

        encrypted = fernet.encrypt(original)

        # deletes unencrypted files if --delete/-d is True.(default=False)
        if args.delete:
            os.remove(file_name)
        else:
            pass

        with open(encrypted_name, 'wb') as file:
            file.write(encrypted)


def decrypt(key):
    fernet = Fernet(key)
    for file_name in os.listdir():
        ext = os.path.splitext(file_name)[1]

        if args.rename:
            decrypted_name = sha1(file_name.encode()).hexdigest() + ext
        else:
            decrypted_name = file_name

        with open(file_name, 'rb') as file:
            encrypted_file = file.read()

        decrypted = fernet.decrypt(encrypted_file)

        # deletes encrypted files if --delete/-d is True.(default=False)
        if args.delete:
            os.remove(file_name)
        else:
            pass

        with open(decrypted_name, 'wb') as file:
            file.write(decrypted)


if __name__ == "__main__":
    change_path()
    key_pass = key_func()
    if args.action == 'enc':
        if args.rename:
            rename()
        encrypt(key_pass)
    elif args.action == 'dec':
        if args.rename:
            rename()
        decrypt(key_pass)

