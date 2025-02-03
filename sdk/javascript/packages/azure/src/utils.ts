import { CryptographyClient, WrapResult } from "@azure/keyvault-keys";
import { randomBytes, createCipheriv, createDecipheriv } from "crypto";
import { AES_256_GCM, BLOB_HEADER, LATIN1_ENCODING, UTF_8_ENCODING, RSA_OEAP } from "./constants";

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
            response = await azureKvStorageCryptoClient.wrapKey(RSA_OEAP, key);
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
            const partBuffer = Buffer.isBuffer(part) ? part : Buffer.from(part, LATIN1_ENCODING);
            const lengthBuffer = Buffer.alloc(2);
            lengthBuffer.writeUInt16BE(partBuffer.length, 0);
            buffers.push(lengthBuffer, partBuffer);
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
            return ""; // Invalid header
        }

        let pos = 2;
        let encryptedKey: Buffer = Buffer.alloc(0);
        let nonce: Buffer = Buffer.alloc(0);
        let tag: Buffer = Buffer.alloc(0);
        let encryptedText: Buffer = Buffer.alloc(0);

        // Step 2: Parse the ciphertext into its components
        for (let i = 1; i <= 4; i++) {
            const sizeBuffer = ciphertext.subarray(pos, pos + 2); // Read the size (2 bytes)
            pos += sizeBuffer.length;

            if (sizeBuffer.length !== 2) break;

            const partLength = sizeBuffer.readUInt16BE(0); // Parse length as big-endian
            const part = ciphertext.subarray(pos, pos + partLength);
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

        // Step 3: Unwrap the AES key using Azure Key Vault
        let key;
        try {
            const response = await azureKeyValueStorageCryptoClient.unwrapKey(RSA_OEAP, encryptedKey);
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
