import { DecryptBufferOptions, EncryptBufferOptions } from "./interface";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { DecryptRequest, EncryptRequest } from "oci-keymanagement/lib/request";
import {
  AES_256_GCM,
  BASE_64,
  BLOB_HEADER,
  LATIN1_ENCODING,
  UTF_8_ENCODING,
} from "./constants";
import { DecryptResponse, EncryptResponse } from "oci-keymanagement/lib/response";
import { calculate } from "fast-crc32c";
import { EncryptDataDetails } from "oci-keymanagement/lib/model";

export async function encryptBuffer(
  options: EncryptBufferOptions
): Promise<Buffer> {
  try {
    // Generate a random 32-byte key
    const key = randomBytes(32);

    // Create AES-GCM cipher instance
    const nonce = randomBytes(16); // AES-GCM requires a 16-byte nonce
    const cipher = createCipheriv(AES_256_GCM, key, nonce);

    // Encrypt the message
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(options.message, UTF_8_ENCODING)),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    const encryptRequest: EncryptRequest = {
      encryptDataDetails: {
        keyId: options.keyId,
        plaintext: key.toString(BASE_64),
      },
    };
    if (options.keyVersionId) {
      encryptRequest.encryptDataDetails.keyVersionId = options.keyVersionId;
    }

    let response: EncryptResponse;
    try {
      response = await options.cryptoClient.encrypt(
        encryptRequest
      );
    } catch (err) {
      if (err?.serviceCode === "InvalidParameter") {
        console.info("since the provided key is not a symmetric key, retrying with RSA key configuration");
        encryptRequest.encryptDataDetails.encryptionAlgorithm = EncryptDataDetails.EncryptionAlgorithm.RsaOaepSha256;
        response = await options.cryptoClient.encrypt(
          encryptRequest
        );
      } else {
        throw err;
      }
    }

    const CiphertextBlob = Buffer.from(Buffer.from(response.encryptedData.ciphertext, BASE_64).toString(LATIN1_ENCODING), LATIN1_ENCODING); // making a latin1 buffer from byte64 buffer

    // Build the blob
    const parts = [CiphertextBlob, nonce, tag, ciphertext];

    const buffers: Buffer[] = [];
    buffers[0] = Buffer.from(BLOB_HEADER, LATIN1_ENCODING);
    for (const part of parts) {
      const lengthBuffer = Buffer.alloc(2);
      lengthBuffer.writeUInt16BE(part.length, 0);
      buffers.push(lengthBuffer, part);
    }
    const blob = Buffer.concat(buffers);

    return blob;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (err: any) {
    console.error("OCI KMS Storage failed to encrypt:", err.message);
    return Buffer.alloc(0); // Return empty buffer in case of an error
  }
}

export async function decryptBuffer(
  options: DecryptBufferOptions
): Promise<string> {
  try {
    // Validate BLOB_HEADER
    const header = Buffer.from(options.ciphertext.subarray(0, 2));
    if (!header.equals(Buffer.from(BLOB_HEADER, LATIN1_ENCODING))) {
      throw new Error("Invalid ciphertext structure: missing header.");
    }

    let pos = 2;
    const parts: Buffer[] = [];

    // Parse the ciphertext into its components
    for (let i = 0; i < 4; i++) {
      const sizeBuffer = options.ciphertext.subarray(pos, pos + 2); // Read the size (2 bytes)
      if (sizeBuffer.length !== 2) {
        throw new Error("Invalid ciphertext structure: size buffer length mismatch.");
      }
      pos += 2;

      const partLength = sizeBuffer.readUInt16BE(0); // Parse length as big-endian
      const part = options.ciphertext.subarray(pos, pos + partLength);
      if (part.length !== partLength) {
        throw new Error("Invalid ciphertext structure: part length mismatch.");
      }
      pos += partLength;

      parts.push(part);
    }

    if (parts.length !== 4) {
      throw new Error("Invalid ciphertext structure: incorrect number of parts.");
    }

    const [encryptedKey, nonce, tag, encryptedText] = parts;

    const decryptOptions: DecryptRequest = {
      decryptDataDetails: {
        keyId: options.keyId,
        ciphertext: Buffer.from(encryptedKey).toString(BASE_64),
      }
    };
    if (options.keyVersionId) {
      decryptOptions.decryptDataDetails.keyVersionId = options.keyVersionId;
    }

    let response: DecryptResponse;
    try {
      response = await options.cryptoClient.decrypt(
        decryptOptions
      );
    } catch (err) {
      if (err?.serviceCode === "InvalidParameter") {
        console.info("since the provided key is not a symmetric key, retrying with RSA key configuration");
        decryptOptions.decryptDataDetails.encryptionAlgorithm = EncryptDataDetails.EncryptionAlgorithm.RsaOaepSha256;
        response = await options.cryptoClient.decrypt(
          decryptOptions
        );
      } else {
        throw err;
      }
    }

    const decryptedKey = response.decryptedData.plaintext;

    const verificationStatus = await verifyDecryption(decryptedKey, response.decryptedData.plaintextChecksum);
    if (verificationStatus) {
      throw new Error("Invalid ciphertext structure: checksum mismatch.");
    }

    const key = Buffer.from(decryptedKey, BASE_64);
    // Decrypt the message using AES-GCM
    const decipher = createDecipheriv(AES_256_GCM, key, nonce);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(encryptedText),
      decipher.final(),
    ]);

    // Convert decrypted data to a UTF-8 string
    return decrypted.toString(UTF_8_ENCODING);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (err: any) {
    console.error("oracle KMS Storage failed to decrypt:", err.message);
    return ""; // Return empty string in case of an error
  }
}


async function verifyDecryption(decryptedData, ociChecksum) {
  const decryptedDataBuffer = Buffer.from(decryptedData, BASE_64);
  const checksum = calculate(decryptedDataBuffer);
  return checksum === ociChecksum;
}
