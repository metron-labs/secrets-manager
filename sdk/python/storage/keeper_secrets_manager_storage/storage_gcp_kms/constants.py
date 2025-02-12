from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class KeyPurpose:
    RAW_ENCRYPT_DECRYPT = "RAW_ENCRYPT_DECRYPT"
    ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT"
    ASYMMETRIC_DECRYPT = "ASYMMETRIC_DECRYPT"

# Supported key purposes
SUPPORTED_KEY_PURPOSE = [
    KeyPurpose.RAW_ENCRYPT_DECRYPT,
    KeyPurpose.ENCRYPT_DECRYPT,
    KeyPurpose.ASYMMETRIC_DECRYPT,
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
