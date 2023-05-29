import os
os.system("apt install python3-pip")
os.system('pip install pycryptodome')
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

inputFile = input("Please write the filepath where the encrypted file exists: ")

inputKeyFile = input("Please write the filepath where the private.pem exists: ")

def decrypt(dataFile, privateKeyFile):
    '''
    use EAX mode to allow detection of unauthorized modifications
    '''

    # this means that the file is in read mode but reads it in binary instead of string.
    with open(privateKeyFile, 'rb') as f:
        privateKey = f.read()
        # create private key object
        # after reading the privatekeyFile, it reads in a "reading" "binary" - 'rb' mode. 
        # then use that binary data into the RSA.import_key() function where it takes that data and creates a RSA object key. (usually takes a key in a format like PEM and returns a key object)
        # this is required so that key object can be used for cryptographic operations.
        key = RSA.import_key(privateKey)

    # read data from file
    with open(dataFile, 'rb') as f:
        # read the session key
        # the file is in a fixed length that's why we are specifying it like this. 
        encryptedSessionKey, nonce, tag, ciphertext = [ f.read(x) for x in (key.size_in_bytes(), 16, 16, -1) ]

    # decrypt the session key
    cipher = PKCS1_OAEP.new(key)
    sessionKey = cipher.decrypt(encryptedSessionKey)

    # decrypt the data with the session key
    cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)

    # this is making sure when we are decrypting, we are using the "tag" produced from EAX mode to check for authenticity and integrity of the data.
    data = cipher.decrypt_and_verify(ciphertext, tag)

    # save the decrypted data to file
    # .split creates a list output
    [ fileName, fileExtension ] = dataFile.split('.')
    decryptedFile = fileName + '_decrypted.' + fileExtension
    with open(decryptedFile, 'wb') as f:
        f.write(data)

    print('Decrypted file saved to ' + decryptedFile)

decrypt(inputFile,inputKeyFile)