import base64
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from .constants import BLOB_HEADER, UTF_8_ENCODING
from oci.exceptions import ServiceError



try:
    from oci.key_management import KmsCryptoClient
    from oci.key_management.models import DecryptDataDetails,EncryptDataDetails
except ImportError:
    logging.getLogger().error("Missing oracle dependencies, import dependencies."
                              " To install missing packages run: \r\n"
                              "pip install oci\r\n")
    raise Exception("Missing import dependencies: oci")


def encrypt_buffer(key_id, message, crypto_client, key_version_id=None):
    try:
        # Generate a random 32-byte key
        key = get_random_bytes(32)

        # Create AES-GCM cipher instance
        cipher = AES.new(key, AES.MODE_GCM)

        # Encrypt the message
        ciphertext, tag = cipher.encrypt_and_digest(
            message.encode())

    
        encrypt_data_details= EncryptDataDetails(
                key_id= key_id,
                plaintext= base64.b64encode(key).decode(UTF_8_ENCODING),
            )
        if key_version_id:
            encrypt_data_details.key_version_id = key_version_id

        try:
            encrypt_response = crypto_client.encrypt(encrypt_data_details)
        except ServiceError as e:
            logging.getLogger().info("since the provided key is not a symmetric key, retrying with RSA key configuration")
            if e.code == "InvalidParameter":
                encrypt_data_details.encryption_algorithm = EncryptDataDetails.ENCRYPTION_ALGORITHM_RSA_OAEP_SHA_256
                encrypt_response = crypto_client.encrypt(encrypt_data_details)
            else:
                raise e
        except Exception as e:
            logging.getLogger().error("Failed to encrypt data: {e}")
            return b''
        finally:
            encrypted_key = base64.b64decode(encrypt_response.data.ciphertext)

        
        parts = [encrypted_key, cipher.nonce, tag, ciphertext]

        buffers = bytearray()
        buffers.extend(BLOB_HEADER)
        for part in parts:
            length_buffer = len(part).to_bytes(2, byteorder='big')
            buffers.extend(length_buffer)
            buffers.extend(part)

        return buffers
    except Exception as err:
        print(f"KCP KMS Storage failed to encrypt: {err}")
        return b''  # Return empty buffer in case of an error

def decrypt_buffer(key_id : str, ciphertext : str,  crypto_client: KmsCryptoClient, key_version_id: str):
    try:
        # Validate BLOB_HEADER
        header = ciphertext[:2]
        if header != BLOB_HEADER:
            raise ValueError("Decryption failed: Invalid header")

        pos = 2
        parts = []

        # Parse the ciphertext into its components
        encrypted_key, nonce, tag, encrypted_text = (b'', b'', b'', b'')
        for x in range(1, 5):
            buf = ciphertext[pos:pos + 2]  # chunks are size prefixed
            pos += len(buf)
            if len(buf) == 2:
                buflen = int.from_bytes(buf, byteorder='big')
                buf = ciphertext[pos:pos + buflen]
                pos += len(buf)
                if len(buf) == buflen:
                    parts.append(buf)
                else:
                    logging.error("Decryption buffer contains incomplete data.")

        encrypted_key, nonce, tag, encrypted_text = parts

        decrpt_data  = DecryptDataDetails(key_id= key_id, ciphertext= base64.b64encode(encrypted_key).decode())
        if key_version_id:
            decrpt_data.key_version_id = key_version_id
        
        try:
            encrypt_response = crypto_client.decrypt(decrypt_data_details=decrpt_data)
        except ServiceError as e:
            logging.getLogger().info("since the provided key is not a symmetric key, retrying with RSA key configuration")
            if e.code == "InvalidParameter":
                decrpt_data.encryption_algorithm = EncryptDataDetails.ENCRYPTION_ALGORITHM_RSA_OAEP_SHA_256
                encrypt_response = crypto_client.decrypt(decrypt_data_details=decrpt_data)
            else:
                raise e
        except Exception as e:
            logging.getLogger().error("Failed to decrypt data: {e}")
            return b''
        finally:
            key = base64.b64decode(encrypt_response.data.plaintext)
    
    
        # Decrypt the message using AES-GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(encrypted_text, tag)

        # Convert decrypted data to a UTF-8 string
        return decrypted.decode()
    except Exception as err:
        print(f"Oracle KMS KeyVault Storage failed to decrypt: {err}")
        return ""  # Return empty string in case of an error
