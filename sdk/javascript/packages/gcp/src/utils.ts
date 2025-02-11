import {
  DecryptBufferOptions,
  decryptOptions,
  EncryptBufferOptions,
  encryptOptions,
} from "./interface/UtilOptions";

import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { calculate } from "fast-crc32c";
import {
  AES_256_GCM,
  BLOB_HEADER,
  LATIN1_ENCODING,
  SHA_256,
  UTF_8_ENCODING,
} from "./constants";
import { publicEncrypt } from "crypto";
import { RSA_PKCS1_OAEP_PADDING } from "constants";


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
      cipher.update(options.message),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    const encryptOptions  = {
      message: key,
      cryptoClient: options.cryptoClient,
      keyProperties : options.keyProperties,
      isAsymmetric: options.isAsymmetric,
    }

    const encryptedResponse: Buffer = options.isAsymmetric ? await encryptDataAndValidateCRCAsymmetric(encryptOptions) : await encryptDataAndValidateCRC(encryptOptions);

    const CiphertextBlob = encryptedResponse;
    // Build the blob
    const parts = [CiphertextBlob, nonce, tag, ciphertext];

    const buffers: Buffer[] = [];
    buffers[0] = Buffer.from(BLOB_HEADER, LATIN1_ENCODING);
    for (const part of parts) {
      const partBuffer = Buffer.isBuffer(part)
        ? part
        : Buffer.from(part, LATIN1_ENCODING);
      const lengthBuffer = Buffer.alloc(2);
      lengthBuffer.writeUInt16BE(partBuffer.length, 0);
      buffers.push(lengthBuffer, partBuffer);
    }
    const blob = Buffer.concat(buffers);

    return blob;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (err: any) {
    console.error("KCP KMS Storage failed to encrypt:", err.message);
    return Buffer.alloc(0); // Return empty buffer in case of an error
  }
}

async function encryptDataAndValidateCRCAsymmetric(
  options: encryptOptions
): Promise<Buffer<ArrayBufferLike>> {
  const keyName = options.keyProperties.toResourceName();
  const encodedData = options.message;

  // Get public key from Cloud KMS
  const [publicKey] = await options.cryptoClient.getPublicKey({
    name: keyName,
  });

  if (publicKey.name !== keyName) {
    throw new Error('GetPublicKey: request corrupted in-transit');
  }
  if (calculate(publicKey.pem) !== Number(publicKey.pemCrc32c.value)) {
    throw new Error('GetPublicKey: response corrupted in-transit');
  }

  const ciphertextBuffer = publicEncrypt(
    {
      key: publicKey.pem,
      oaepHash: SHA_256,
      padding: RSA_PKCS1_OAEP_PADDING,
    },
    encodedData
  );

  console.log(`Ciphertext: ${ciphertextBuffer.toString('base64')}`);
  return ciphertextBuffer;
}

async function encryptDataAndValidateCRC(
  options: encryptOptions
): Promise<Buffer<ArrayBufferLike>> {
  const keyName = options.keyProperties.toResourceName();
  const encodedData = options.message;
  const encodedDataCrc = calculate(encodedData);

  const KMSClient = options.cryptoClient;
  const input = {
    name: keyName,
    plaintext: encodedData,
    plaintextCrc32c: {
      value: encodedDataCrc,
    },
  };

  const [encryptResponse] = await KMSClient.encrypt(input);
  const ciphertext = encryptResponse.ciphertext;
  const cipherTextCrc = calculate(Buffer.from(ciphertext));
  if (!encryptResponse.verifiedPlaintextCrc32c) {
    throw new Error("Encrypt: request corrupted in-transit");
  }
  if (cipherTextCrc !== Number(encryptResponse.ciphertextCrc32c.value)) {
    throw new Error("Encrypt: response corrupted in-transit");
  }

  const cipherTextBuffer = typeof ciphertext === "string" ? Buffer.from(ciphertext.toString(), LATIN1_ENCODING) : Buffer.from(ciphertext);

  return cipherTextBuffer;
}

export async function decryptBuffer(
  options: DecryptBufferOptions
): Promise<string> {
  try {
    // Validate BLOB_HEADER
    const header = Buffer.from(options.ciphertext.subarray(0, 2));
    if (!header.equals(Buffer.from(BLOB_HEADER, LATIN1_ENCODING))) {
      return ""; // Invalid header
    }

    let pos = 2;
    let encryptedKey: Buffer = Buffer.alloc(0);
    let nonce: Buffer = Buffer.alloc(0);
    let tag: Buffer = Buffer.alloc(0);
    let encryptedText: Buffer = Buffer.alloc(0);

    // Parse the ciphertext into its components
    for (let i = 1; i <= 4; i++) {
      const sizeBuffer = options.ciphertext.subarray(pos, pos + 2); // Read the size (2 bytes)
      pos += sizeBuffer.length;

      if (sizeBuffer.length !== 2) break;

      const partLength = sizeBuffer.readUInt16BE(0); // Parse length as big-endian
      const part = options.ciphertext.subarray(pos, pos + partLength);
      pos += part.length;

      if (part.length !== partLength) {
        throw new Error("Invalid ciphertext structure: part length mismatch.");
      }

      // Assign the parsed part to the appropriate variable
      switch (i) {
        case 1:
          encryptedKey = part;
          break;
        case 2:
          nonce = part;
          break;
        case 3:
          tag = part;
          break;
        case 4:
          encryptedText = part;
          break;
        default:
          console.error("Google KSM decrypt buffer contains extra data.");
      }
    }

    const decryptedData = await decryptDataAndValidateCRC({
      cipherText: encryptedKey,
      cryptoClient: options.cryptoClient,
      keyProperties : options.keyProperties,
      isAsymmetric: options.isAsymmetric,
    });

    const key = decryptedData;
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
    console.error("Google KMS KeyVault Storage failed to decrypt:", err.message);
    return ""; // Return empty string in case of an error
  }
}

async function decryptDataAndValidateCRC(
  options: decryptOptions
): Promise<Buffer<ArrayBufferLike>> {
  const keyName = options.keyProperties.toKeyName();
  const cipherData = options.cipherText;
  const cipherDataCRC = calculate(cipherData);

  const KMSClient = options.cryptoClient;
  const input = {
    name: keyName,
    ciphertext: cipherData,
    ciphertextCrc32c: {
      value: cipherDataCRC,
    },
  };
  let decryptResponseData;
  if (options.isAsymmetric){
    const keyNameForAsymmetricDecrypt = options.keyProperties.toResourceName();
    input.name = keyNameForAsymmetricDecrypt
    const [decryptResponse] = await KMSClient.asymmetricDecrypt(input);
    decryptResponseData = decryptResponse
  }else{
    const [decryptResponse] = await KMSClient.decrypt(input);
    decryptResponseData = decryptResponse
  }

  if (
    calculate(decryptResponseData.plaintext) !==
    Number(decryptResponseData.plaintextCrc32c.value)
  ) {
    throw new Error("Decrypt: response corrupted in-transit");
  }
  const plaintext = decryptResponseData.plaintext;

  return typeof plaintext === "string" ? Buffer.from(plaintext.toString(), LATIN1_ENCODING) : Buffer.from(plaintext);
}
