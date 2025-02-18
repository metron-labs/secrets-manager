from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from google.cloud.kms_v1 import CryptoKey

class KeyPurpose:
    RAW_ENCRYPT_DECRYPT = CryptoKey.CryptoKeyPurpose.RAW_ENCRYPT_DECRYPT
    ENCRYPT_DECRYPT = CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
    ASYMMETRIC_DECRYPT = CryptoKey.CryptoKeyPurpose.ASYMMETRIC_DECRYPT
    
# Supported key purposes
SUPPORTED_KEY_PURPOSE = [
    CryptoKey.CryptoKeyPurpose.RAW_ENCRYPT_DECRYPT,
    CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
    CryptoKey.CryptoKeyPurpose.ASYMMETRIC_DECRYPT,
]

# Constants
BLOB_HEADER = b"\xff\xff"  # Encrypted BLOB Header: U+FFFF is a non-character
LATIN1_ENCODING = "latin1"
UTF_8_ENCODING = "utf-8"
AES_256_GCM = "aes-256-gcm"
MD5_HASH = "md5"
HEX_DIGEST = "hex"
DEFAULT_JSON_INDENT = 4
OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)
SHA_256 = hashes.SHA256()
