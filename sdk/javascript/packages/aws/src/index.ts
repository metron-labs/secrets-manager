import { DefaultAzureCredential, ClientSecretCredential } from "@azure/identity";
import { CryptographyClient, WrapResult } from "@azure/keyvault-keys";

import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { dirname } from 'path';
import { randomBytes, createCipheriv, createDecipheriv, createHash } from 'crypto';
import { KeyValueStorage, platform } from "@keeper-security/secrets-manager-core";

import {AWSSessionConfig} from './AwsSessionConfig';
import {EncryptResponse, KMSClient} from '@aws-sdk/client-kms';
import {AWSKeyValueStorageError} from './error';
import { AwsKmsClient } from "./AwsKmsClient";
import { EncryptionAlgorithmEnum } from "./enum";
import { DecryptResponse } from "./interface/DecryptResponse";


export class AWSKeyValueStorage implements KeyValueStorage {

    defaultConfigFileLocation: string = "client-config.json";
    keyId!: string;
    azureCredentials!: ClientSecretCredential | DefaultAzureCredential;
    cryptoClient!: : KMSClient;
    last_saved_config_hash!: string;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    config: Record<string, any> = {};
    lastSavedConfigHash!: string;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    logger: any;
    encryptionAlgoithm : string;
    awsCredentials!: AWSSessionConfig;

    getDefaultLogger() {
        this.logger = console
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

    constructor(keyId: string, configFileLocation: string | null, awsSessionConfig: AWSSessionConfig | null) {
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

        if (awsSessionConfig) {
            const hasAzureSessionConfig = awsSessionConfig.awsAccessKeyId && awsSessionConfig.awsSecretAccessKey && awsSessionConfig.regionName;
            if (hasAzureSessionConfig) {
                this.awsCredentials  = awsSessionConfig;
            } else {
                throw new AWSKeyValueStorageError("Missing aws session config/session config is not valid");
            }
        }
        this.cryptoClient = new AwsKmsClient(this.awsCredentials);

        this.lastSavedConfigHash = "";
        this.encryptionAlgoithm = EncryptionAlgorithmEnum.RSAES_OAEP_SHA_256 // default recommended by AWS
    }

    async init() {
        await this.loadConfig();
        this.logger.info(`Loaded config file from ${this.defaultConfigFileLocation}`);
        return this; // Return the instance to allow chaining
    }

    private async encryptBuffer(message: string): Promise<Buffer> {
        try {
            const encryptCommandOptions = {
                KeyId : this.keyId,
                Plaintext : message,
                EncryptionAlgorithm : this.encryptionAlgoithm
            }
            let response : EncryptResponse = await this.cryptoClient.encryptCommand(encryptCommandOptions);
            const CiphertextBlob = response.CiphertextBlob ?? "";
            if (CiphertextBlob.length === 0) {
                console.error("AWS KMS Storage failed to encrypt: CiphertextBlob is empty");
                return Buffer.alloc(0); // Return empty buffer in case of an error
            }
            return Buffer.from(CiphertextBlob)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            console.error("AWS KMS Storage failed to encrypt:", err.message);
            return Buffer.alloc(0); // Return empty buffer in case of an error
        }
    }

    private async decryptBuffer(ciphertext: Buffer): Promise<string> {
        try{
            const decryptCommandOptions = {
                "CiphertextBlob": ciphertext,
                "EncryptionAlgorithm": this.encryptionAlgoithm,
                "KeyId": this.keyId
            }
            let response: DecryptResponse = this.cryptoClient.decryptCommand(decryptCommandOptions); 
            
            let decryptedData = response.Plaintext ?? "";
            if (decryptedData.length === 0) {
                console.error("AWS KMS Storage failed to decrypt: decryptedData is empty");
                return ""; // Return empty string in case of an error
            }
            
            return decryptedData
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            console.error("Azure KeyVault Storage failed to decrypt:", err.message);
            return ""; // Return empty string in case of an error
        }
    }

    private async loadConfig(): Promise<void> {
        await this.createConfigFileIfMissing();

        try {
            // Step 1: Read the config file
            let contents: Buffer = Buffer.alloc(0);
            try {
                contents = readFileSync(this.defaultConfigFileLocation);
                this.logger.info(`Loaded config file ${this.defaultConfigFileLocation}`);
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            } catch (err: any) {
                this.logger.error(`Failed to load config file ${this.defaultConfigFileLocation}: ${err.message}`);
                throw new Error(`Failed to load config file ${this.defaultConfigFileLocation}`);
            }

            if (contents.length === 0) {
                this.logger.warn(`Empty config file ${this.defaultConfigFileLocation}`);
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
            await this.createConfigFileIfMissing();

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
                this.logger.warn(`Empty config file ${this.defaultConfigFileLocation}`);
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
    public async readStorage(): Promise<Record<string, any>> {
        if (!this.config) {
            await this.loadConfig();
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
        await this.saveStorage(config);
        return Promise.resolve();
    }

    public async deleteAll(): Promise<void> {
        await this.readStorage();
        Object.keys(this.config).forEach(key => delete this.config[key]);
        await this.saveStorage({});
        return Promise.resolve();
    }

    public async contains(key: string): Promise<boolean> {
        const config = await this.readStorage();
        return Promise.resolve(key in Object.keys(config));
    }

    public async isEmpty(): Promise<boolean> {
        const config = await this.readStorage();
        return Promise.resolve(Object.keys(config).length === 0);
    }
}