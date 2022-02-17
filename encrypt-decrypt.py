import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import json


# Encrypting the given file using AES and creating a new encrypted file
def encrypt(key, filename):
    chunksize = 64 * 1024
    outputFile = "(encrypted)" + filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)

    data_dict = {filename: str(key)[2:-1]}
    try:
        with open("data.json", "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        with open("data.json", "w") as file:
            json.dump(data_dict, file, indent=4)
    else:
        data.update(data_dict)

        with open("data.json", "w") as file:
            json.dump(data, file, indent=4)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))


# Decrypting the given encrypted file using AES and creating a decrypted(original) file
def decrypt(key, filename):
    chunksize = 64 * 1024
    outputFile = filename[11:]

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)


# Creating a secret key by hashing the password using SHA256
def getKey(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()


def Main():
    choice = input("Would you like to (E)ncrypt or (D)ecrypt?: ")
    if choice == 'E' or choice == 'e':
        filename = input("File to encrypt: ")
        password = input("Password: ")
        encrypt(getKey(password), filename)
        # Deleting the file after encryption
        os.remove(filename)
        print("Done.")
    elif choice == 'D' or choice == 'd':
        filename = input("File to decrypt: ")
        password = input("Password: ")
        hashed = getKey(password)
        hashed = str(hashed)[2:-1]
        try:
            with open("data.json", "r") as file:
                data = json.load(file)
        except FileNotFoundError:
            print("File does not exist.")
        else:
            if filename[11:] in data:
                if data[filename[11:]] == hashed:
                    decrypt(getKey(password), filename)
                    # Deleting the encrypted  file after decryption
                    os.remove(filename)
                    print("Done.")
                else:
                    print("Wrong password.")
            else:
                print("File does not  exist.")

    else:
        print("No Option selected, closing...")


if __name__ == '__main__':
    Main()
