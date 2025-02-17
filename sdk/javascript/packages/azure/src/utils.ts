import { CryptographyClient, WrapResult } from "@azure/keyvault-keys";
import { randomBytes, createCipheriv, createDecipheriv } from "crypto";
import { AES_256_GCM, BLOB_HEADER, LATIN1_ENCODING, UTF_8_ENCODING, RSA_OAEP } from "./constants";

export async function encryptBuffer(azureKvStorageCryptoClient: CryptographyClient, message: string): Promise<Buffer> {
    try {
        // Step 1: Generate a random 32-byte key
        const key = randomBytes(32);

        // Step 2: Create AES-GCM cipher instance
        const nonce = randomBytes(16); // AES-GCM requires a 16-byte nonce
        const cipher = createCipheriv(AES_256_GCM, key, nonce);

        // Step 3: Encrypt the message
        const ciphertext = Buffer.concat([cipher.update(Buffer.from(message, UTF_8_ENCODING)), cipher.final()]);
        const tag = cipher.getAuthTag();

        // Step 4: Wrap the AES key using Azure Key Vault
        let wrappedKey;
        let response: WrapResult;
        try {
            response = await azureKvStorageCryptoClient.wrapKey(RSA_OAEP, key);
            wrappedKey = response.result; // The wrapped (encrypted) AES key

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            console.error("Azure crypto client failed to wrap key:", err.message);
            return Buffer.alloc(0); // Return empty buffer in case of an error
        }

        // Step 5: Build the blob
        const parts = [wrappedKey, nonce, tag, ciphertext];

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
        console.error("Azure KeyVault Storage failed to encrypt:", err.message);
        return Buffer.alloc(0); // Return empty buffer in case of an error
    }
}


export async function decryptBuffer(azureKeyValueStorageCryptoClient: CryptographyClient, ciphertext: Buffer): Promise<string> {
    try {
        // Step 1: Validate BLOB_HEADER
        const header = Buffer.from(ciphertext.subarray(0, 2));
        if (!header.equals(Buffer.from(BLOB_HEADER, LATIN1_ENCODING))) {
            throw new Error("Invalid ciphertext structure: missing header."); // Invalid header
        }

        let pos = 2;
        const parts: Buffer[] = [];

        // Parse the ciphertext into its components
        for (let i = 0; i < 4; i++) {
        const sizeBuffer = ciphertext.subarray(pos, pos + 2); // Read the size (2 bytes)
        if (sizeBuffer.length !== 2) {
        throw new Error("Invalid ciphertext structure: size buffer length mismatch.");
        }
        pos += 2;

        const partLength = sizeBuffer.readUInt16BE(0); // Parse length as big-endian
        const part = ciphertext.subarray(pos, pos + partLength);
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


        // Step 3: Unwrap the AES key using Azure Key Vault
        let key;
        try {
            const response = await azureKeyValueStorageCryptoClient.unwrapKey(RSA_OAEP, encryptedKey);
            key = response.result; // Unwrapped AES key

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            console.error("Azure crypto client failed to unwrap key:", err.message);
            return ""; // Return empty string in case of an error
        }

        // Step 4: Decrypt the message using AES-GCM
        const decipher = createDecipheriv(AES_256_GCM, key, nonce);
        decipher.setAuthTag(tag);

        const decrypted = Buffer.concat([
            decipher.update(encryptedText),
            decipher.final(),
        ]);

        // Step 5: Convert decrypted data to a UTF-8 string
        return decrypted.toString(UTF_8_ENCODING);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        console.error("Azure KeyVault Storage failed to decrypt:", err.message);
        return ""; // Return empty string in case of an error
    }
}