import os
os.system("apt install python3-pip")
os.system('pip install pycryptodome')

# importing RSA algorithm
from Crypto.PublicKey import RSA

# creating the keys with 2048 bits
key = RSA.generate(2048)

# assuming that the key itself is the private key.
# and the subcomponent of key.publickey() is the public key.
privateKey = key.export_key()
publicKey = key.publickey().export_key()

# saving the private key to a .pem file using binary.
with open('private.pem','wb') as f:
    f.write(privateKey)

# same thing as private key but for public key
with open('public.pem','wb') as f:
    f.write(publicKey)

# when you run this software, you get two riles, private and public key pem files. 



