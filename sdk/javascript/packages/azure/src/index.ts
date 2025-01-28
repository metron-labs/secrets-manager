import { DefaultAzureCredential, ClientSecretCredential } from "@azure/identity";
import { CryptographyClient } from "@azure/keyvault-keys";
import { KnownEncryptionAlgorithms } from "@azure/keyvault-keys";

import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { dirname } from 'path';
import { randomBytes, createCipheriv, createDecipheriv, createHash } from 'crypto';
import { KeyValueStorage, platform } from "@keeper-security/secrets-manager-core";


const BLOB_HEADER = "\xff\xff"; // Encrypted BLOB Header: U+FFFF is a noncharacter

export class AzureSessionConfig {
    tenant_id: string;
    client_id: string;
    client_secret: string;

    constructor(tenant_id: string, client_id: string, client_secret: string) {
        this.tenant_id = tenant_id;
        this.client_id = client_id;
        this.client_secret = client_secret;
    }
}

export class AzureKeyValueStorage implements KeyValueStorage {

    defaultConfigFileLocation: string = "client-config.json";
    keyId!: string;
    azureCredentials!: ClientSecretCredential | DefaultAzureCredential;
    cryptoClient!: CryptographyClient;
    last_saved_config_hash!: string;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    config: Record<string, any> = {};
    lastSavedConfigHash!: string;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    logger: any;

    getDefaultLogger() {
        if (!this.logger) {
            return {
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
              info: (message: any) => console.info(`[INFO]: ${message}`),
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              warn: (message: any) => console.warn(`[WARN]: ${message}`),
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              error: (message: any) => console.error(`[ERROR]: ${message}`),
            };
        }else{
            return this.logger
        }
      }

    getString(key: string): Promise<string | undefined> {
        return this.get(key);
    }
    saveString(key: string, value: string): Promise<void> {
        return this.set(key, value);
    }
    async getBytes(key: string): Promise<Uint8Array | undefined> {
        const bytesString = await this.get(key);
        if (bytesString) {
            return Promise.resolve(platform.base64ToBytes(bytesString));
        }
        return Promise.resolve(undefined);
    }
    saveBytes(key: string, value: Uint8Array): Promise<void> {
        const bytesString = platform.bytesToBase64(value);
        return this.set(key, bytesString);
    }

    getObject?<T>(key: string): Promise<T | undefined> {
        return this.getString(key).then((value) => value ? JSON.parse(value) as T : undefined);
    }
    saveObject?<T>(key: string, value: T): Promise<void> {
        const json = JSON.stringify(value);
        return this.saveString(key, json);
    }

    Constructor(keyId: string, configFileLocation: string | null, azSessionConfig: AzureSessionConfig | null) {
        /** 
        Initilaizes AzureKeyValueStorage

        key_id URI of the master key - if missing read from env KSM_AZ_KEY_ID
        key_id URI may also include version in case key has auto rotate enabled
        ex. key_id = "https://<your vault>.vault.azure.net/keys/<key name>/fe4fdcab688c479a9aa80f01ffeac26"
        The master key needs WrapKey, UnwrapKey privileges

        config_file_location provides custom config file location - if missing read from env KSM_CONFIG_FILE
        az_session_config optional az session config - if missing use default env variables
        https://learn.microsoft.com/en-us/dotnet/api/azure.identity.environmentcredential
        **/
        this.defaultConfigFileLocation = configFileLocation ?? process.env.KSM_CONFIG_FILE ?? this.defaultConfigFileLocation;
        this.keyId = keyId ?? process.env.KSM_AZ_KEY_ID;
        this.getDefaultLogger();

        if (azSessionConfig) {
            const hasAzureSessionConfig = azSessionConfig.tenant_id && azSessionConfig.client_id && azSessionConfig.client_secret;
            if (hasAzureSessionConfig) {
                this.azureCredentials = new ClientSecretCredential(azSessionConfig.tenant_id, azSessionConfig.client_id, azSessionConfig.client_secret);
            } else {
                this.azureCredentials = new DefaultAzureCredential();
            }
        }
        this.cryptoClient = new CryptographyClient(this.keyId, this.azureCredentials);

        this.last_saved_config_hash = "";
        this.config = {};
        this.loadConfig()
        

    }

    private async encryptBuffer(message: string): Promise<Buffer> {
        try {
            // Step 1: Generate a random 32-byte key
            const key = randomBytes(32);

            // Step 2: Create AES-GCM cipher instance
            const nonce = randomBytes(12); // AES-GCM requires a 12-byte nonce
            const cipher = createCipheriv('aes-256-gcm', key, nonce);

            // Step 3: Encrypt the message
            const ciphertext = Buffer.concat([cipher.update(Buffer.from(message, 'utf-8')), cipher.final()]);
            const tag = cipher.getAuthTag();

            // Step 4: Wrap the AES key using Azure Key Vault
            let wrappedKey: Buffer;
            try {
                const response = await this.cryptoClient.wrapKey(KnownEncryptionAlgorithms.RSAOaep, key);
                wrappedKey = Buffer.from(response.result); // The wrapped (encrypted) AES key
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            } catch (err: any) {
                console.error("Azure crypto client failed to wrap key:", err.message);
                return Buffer.alloc(0); // Return empty buffer in case of an error
            }

            // Step 5: Build the blob
            let blob = Buffer.from(BLOB_HEADER); // Start with the header
            const parts = [wrappedKey, nonce, tag, ciphertext];

            for (const part of parts) {
                const lengthBuffer = Buffer.alloc(2); // 2 bytes for length
                lengthBuffer.writeUInt16BE(part.length, 0);
                blob = Buffer.concat([blob, lengthBuffer, part]);
            }

            return blob;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            console.error("Azure KeyVault Storage failed to encrypt:", err.message);
            return Buffer.alloc(0); // Return empty buffer in case of an error
        }
    }

    private async decryptBuffer(ciphertext: Buffer): Promise<string> {
        try {
            // Step 1: Validate BLOB_HEADER
            const header = ciphertext.subarray(0, 2);
            if (!header.equals(Buffer.from(BLOB_HEADER))) {
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
            let key: Buffer;
            try {
                const response = await this.cryptoClient.unwrapKey(KnownEncryptionAlgorithms.RSAOaep, encryptedKey);
                key = Buffer.from(response.result); // Unwrapped AES key
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            } catch (err: any) {
                console.error("Azure crypto client failed to unwrap key:", err.message);
                return ""; // Return empty string in case of an error
            }

            // Step 4: Decrypt the message using AES-GCM
            const decipher = createDecipheriv('aes-256-gcm', key, nonce);
            decipher.setAuthTag(tag);

            const decrypted = Buffer.concat([
                decipher.update(encryptedText),
                decipher.final(),
            ]);

            // Step 5: Convert decrypted data to a UTF-8 string
            return decrypted.toString('utf-8');
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            console.error("Azure KeyVault Storage failed to decrypt:", err.message);
            return ""; // Return empty string in case of an error
        }
    }

    private async loadConfig(): Promise<void> {
        this.createConfigFileIfMissing();

        try {
            // Step 1: Read the config file
            let contents: Buffer = Buffer.alloc(0);
            try {
                contents = readFileSync(this.defaultConfigFileLocation);
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            } catch (err: any) {
                this.logger.error(`Failed to load config file ${this.defaultConfigFileLocation}: ${err.message}`);
                throw new Error(`Failed to load config file ${this.defaultConfigFileLocation}`);
            }

            if (contents.length === 0) {
                this.logger.warning(`Empty config file ${this.defaultConfigFileLocation}`);
            }

            // Step 2: Check if the content is plain JSON
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            let config: Record<string, any> | null = null;
            if (this.isJson(contents)) {
                try {
                    const configData = contents.toString();
                    config = JSON.parse(configData);
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                } catch (err: any) {
                    this.logger.error(`Config file is not a valid JSON file: ${err.message}`);
                    throw new Error(`${this.defaultConfigFileLocation} may contain JSON format problems`);
                }

                // Encrypt and save the config if it's plain JSON
                if (config) {
                    this.config = config;
                    await this.saveConfig(config);
                    this.lastSavedConfigHash = createHash('md5').update(JSON.stringify(config, null, 4)).digest('hex');
                }
            } else {
                // Step 3: Attempt to decrypt the binary blob
                const configJson = await this.decryptBuffer(contents);
                try {
                    config = JSON.parse(configJson);
                    this.config = config ?? {};
                    this.lastSavedConfigHash = createHash('md5').update(JSON.stringify(config, null, 4)).digest('hex');
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                } catch (err: any) {
                    this.logger.error(`Failed to parse decrypted config file: ${err.message}`);
                    throw new Error(`Failed to parse decrypted config file ${this.defaultConfigFileLocation}`);
                }
            }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            this.logger.error(`Error loading config: ${err.message}`);
            throw err;
        }
    }

    private async saveConfig(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        updatedConfig: Record<string, any> = {},
        force = false
    ): Promise<void> {
        try {
            // Step 1: Retrieve current config
            const config = this.config || {};
            const configJson = JSON.stringify(config, null, 4);
            let configHash = createHash('md5').update(configJson).digest('hex');

            // Step 2: Compare updatedConfig hash with current config hash
            if (Object.keys(updatedConfig).length > 0) {
                const updatedConfigJson = JSON.stringify(updatedConfig, null, 4);
                const updatedConfigHash = createHash('md5')
                    .update(updatedConfigJson)
                    .digest('hex');

                if (updatedConfigHash !== configHash) {
                    configHash = updatedConfigHash;
                    this.config = { ...updatedConfig }; // Update the current config
                }
            }

            // Step 3: Check if saving is necessary
            if (!force && configHash === this.lastSavedConfigHash) {
                console.warn("Skipped config JSON save. No changes detected.");
                return;
            }

            // Step 4: Ensure the config file exists
            this.createConfigFileIfMissing();

            // Step 5: Encrypt the config JSON and write to the file
            const blob = await this.encryptBuffer(JSON.stringify(this.config, null, 4));
            writeFileSync(this.defaultConfigFileLocation, blob);

            // Step 6: Update the last saved config hash
            this.lastSavedConfigHash = configHash;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            console.error("Error saving config:", err.message);
        }
    }

    public async decryptConfig(autosave: boolean = true): Promise<string> {
        let ciphertext: Buffer = Buffer.alloc(0);
        let plaintext: string = "";

        try {
            // Step 1: Read the config file
            ciphertext = readFileSync(this.defaultConfigFileLocation);
            if (ciphertext.length === 0) {
                this.logger.warning(`Empty config file ${this.defaultConfigFileLocation}`);
                return "";
            }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            this.logger.error(`Failed to load config file ${this.defaultConfigFileLocation}: ${err.message}`);
            throw new Error(`Failed to load config file ${this.defaultConfigFileLocation}`);
        }

        try {
            // Step 2: Decrypt the file contents
            plaintext = await this.decryptBuffer(ciphertext);
            if (plaintext.length === 0) {
                this.logger.error(`Failed to decrypt config file ${this.defaultConfigFileLocation}`);
            } else if (autosave) {
                // Step 3: Optionally autosave the decrypted content
                writeFileSync(this.defaultConfigFileLocation, plaintext);
            }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            this.logger.error(`Failed to write decrypted config file ${this.defaultConfigFileLocation}: ${err.message}`);
            throw new Error(`Failed to write decrypted config file ${this.defaultConfigFileLocation}`);
        }

        return plaintext;
    }

    private isJson(content: Buffer): boolean {
        try {
            JSON.parse(content.toString());
            return true;
        } catch {
            return false;
        }
    }


    public async changeKey(newKeyId: string): Promise<boolean> {
        const oldKeyId = this.keyId;
        const oldCryptoClient = this.cryptoClient;

        try {
            // Update the key and reinitialize the CryptographyClient
            this.keyId = newKeyId;
            this.cryptoClient = new CryptographyClient(this.keyId, this.azureCredentials);

            await this.saveConfig({}, true);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (error: any) {
            // Restore the previous key and crypto client if the operation fails
            this.keyId = oldKeyId;
            this.cryptoClient = oldCryptoClient;

            // Log the error
            this.logger.error(`Failed to change the key to '${newKeyId}' for config '${this.defaultConfigFileLocation}': ${error.message}`);

            // Rethrow the error with a specific message
            throw new Error(`Failed to change the key for ${this.defaultConfigFileLocation}`);
        }
        return true;
    }

    private async createConfigFileIfMissing(): Promise<void> {
        try {
            // Check if the config file already exists
            if (!existsSync(this.defaultConfigFileLocation)) {
                // Ensure the directory structure exists
                const dir = dirname(this.defaultConfigFileLocation);
                if (!existsSync(dir)) {
                    mkdirSync(dir, { recursive: true });
                }

                // Encrypt an empty configuration and write to the file
                const blob = await this.encryptBuffer("{}");
                writeFileSync(this.defaultConfigFileLocation, blob);
                console.log("Config file created at:", this.defaultConfigFileLocation);
            } else {
                console.log("Config file already exists at:", this.defaultConfigFileLocation);
            }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            console.error("Error creating config file:", err.message);
        }
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    public readStorage(): Promise<Record<string, any>> {
        if (!this.config) {
            this.loadConfig();
        }
        return Promise.resolve(this.config);
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    public saveStorage(updatedConfig: Record<string, any>): Promise<void> {
        return this.saveConfig(updatedConfig);
    }

    public async get(key: string): Promise<string> {
        const config =await this.readStorage();
        return Promise.resolve(config[key]);
    }

    public async set(key: string, value: string): Promise<void> {
        const config = await this.readStorage();
        config[key] = value;
        await this.saveStorage(config);
        return Promise.resolve();
    }

    public async delete(key: string): Promise<void> {
        const config = await this.readStorage();

        if (key in Object.keys(config)) {
            this.logger.debug(`Deleting key ${key} from ${this.defaultConfigFileLocation}`);
            delete config[key];
        } else {
            this.logger.debug(`Key ${key} not found in ${this.defaultConfigFileLocation}`);
        }
        this.saveStorage(config);
        return Promise.resolve();
    }

    public async deleteAll(): Promise<void> {
        await this.readStorage();
        Object.keys(this.config).forEach(key => delete this.config[key]);
        this.saveStorage({});
        return Promise.resolve();
    }

    public contains(key: string): Promise<boolean> {
        const config = this.readStorage();
        return Promise.resolve(key in Object.keys(config));
    }

    public isEmpty(): Promise<boolean> {
        const config = this.readStorage();
        return Promise.resolve(Object.keys(config).length === 0);
    }
}
