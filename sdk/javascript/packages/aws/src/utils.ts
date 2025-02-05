import {
  EncryptResponse,
  EncryptCommand,
  DecryptCommand,
  EncryptCommandInput,
  DecryptCommandOutput,
} from "@aws-sdk/client-kms";
import {
  DecryptBufferOptions,
  EncryptBufferOptions,
} from "./interface/UtilOptions";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import {
  AES_256_GCM,
  BLOB_HEADER,
  LATIN1_ENCODING,
  UTF_8_ENCODING,
} from "./constants";
import { KeySpecEnum } from "./enum";

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

    const encryptCommandOptions: EncryptCommandInput = {
      KeyId: options.keyId,
      Plaintext: key,
      EncryptionAlgorithm: options.encryptionAlgorithm,
    };

    if (options.keyType === KeySpecEnum.SYMMETRIC_DEFAULT) {
      delete encryptCommandOptions.EncryptionAlgorithm;
    }

    const encryptCommandPayload = new EncryptCommand(encryptCommandOptions);
    const response: EncryptResponse = await options.cryptoClient.send(
      encryptCommandPayload
    );
    const CiphertextBlob = Buffer.from(response.CiphertextBlob);
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
    console.error("AWS KMS Storage failed to encrypt:", err.message);
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
          console.error("Azure KeyVault decrypt buffer contains extra data.");
      }
    }

    const decryptCommandOptions = {
      EncryptionAlgorithm: options.encryptionAlgorithm,
      KeyId: options.keyId,
      CiphertextBlob: encryptedKey,
    };

    if (options.keyType === KeySpecEnum.SYMMETRIC_DEFAULT) {
      delete decryptCommandOptions.EncryptionAlgorithm;
    }

    const decryptCommandPayload: DecryptCommand = new DecryptCommand(
      decryptCommandOptions
    );
    const response: DecryptCommandOutput = await options.cryptoClient.send(
      decryptCommandPayload
    );
    const decryptedData = response.Plaintext;

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
    console.error("Azure KeyVault Storage failed to decrypt:", err.message);
    return ""; // Return empty string in case of an error
  }
}
