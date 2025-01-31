import { ClientSecretCredential, DefaultAzureCredential } from "@azure/identity";
import { CryptographyClient } from "@azure/keyvault-keys";
import { KeyValueStorage, platform } from "@keeper-security/secrets-manager-core";
import { AzureSessionConfig } from "./AzureSessionConfig";
import { loadConfig, saveConfig } from "./configHandler";



export class AzureKeyValueStorage implements KeyValueStorage {

    defaultConfigFileLocation: string = "client-config.json";
    keyId!: string;
    azureCredentials!: ClientSecretCredential | DefaultAzureCredential;
    cryptoClient!: CryptographyClient;
    lastSavedConfigHash!: string;
    config: Record<string, string> | null;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    logger: any;
    configFileLocation: string;

    /**
     * Initializes and returns a default logger with typed methods.
     * 
     * @returns {Console | { info: (message: string) => void; warn: (message: string) => void; error: (message: string) => void; }}
     */
    getDefaultLogger(): Console | { info: (message: string) => void; warn: (message: string) => void; error: (message: string) => void; } {
        this.logger = console;
        if (!this.logger) {
            return {
                info: (message: string) => console.info(`[INFO]: ${message}`),
                warn: (message: string) => console.warn(`[WARN]: ${message}`),
                error: (message: string) => console.error(`[ERROR]: ${message}`),
            };
        } else {
            return this.logger;
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
            return platform.base64ToBytes(bytesString);
        }
        return undefined;
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

    constructor(keyId: string, configFileLocation: string | null, azSessionConfig: AzureSessionConfig | null) {
        /**
        Initilaizes AzureKeyValueStorage

        keyId URI of the master key - if missing read from env KSM_AZ_KEY_ID
        keyId URI may also include version in case key has auto rotate enabled
        ex. keyId = "https://<your vault>.vault.azure.net/keys/<key name>/<key_version>"
        The master key needs WrapKey, UnwrapKey privileges

        configFileLocation provides custom config file location - if missing read from env KSM_CONFIG_FILE
        azSessionConfig optional az session config - if missing use default env variables
        https://learn.microsoft.com/en-us/dotnet/api/azure.identity.environmentcredential
        **/
        this.configFileLocation = configFileLocation ?? process.env.KSM_CONFIG_FILE ?? this.defaultConfigFileLocation;
        this.keyId = keyId ?? process.env.KSM_AZ_KEY_ID;
        this.getDefaultLogger();

        if (azSessionConfig) {
            const hasAzureSessionConfig = azSessionConfig.tenantId && azSessionConfig.clientId && azSessionConfig.clientSecret;
            if (hasAzureSessionConfig) {
                this.azureCredentials = new ClientSecretCredential(azSessionConfig.tenantId, azSessionConfig.clientId, azSessionConfig.clientSecret);
            } else {
                this.azureCredentials = new DefaultAzureCredential();
            }
        }
        this.cryptoClient = new CryptographyClient(this.keyId, this.azureCredentials);

        this.lastSavedConfigHash = "";
    }

    async init() {
        await loadConfig(this);
        return this; // Return the instance to allow chaining
    }

    public async changeKey(newKeyId: string): Promise<boolean> {
        const oldKeyId = this.keyId;
        const oldCryptoClient = this.cryptoClient;

        try {
            // Update the key and reinitialize the CryptographyClient
            this.keyId = newKeyId;
            this.cryptoClient = new CryptographyClient(this.keyId, this.azureCredentials);

            await saveConfig(this, {}, true);
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (error: any) {
            // Restore the previous key and crypto client if the operation fails
            this.keyId = oldKeyId;
            this.cryptoClient = oldCryptoClient;

            // Log the error
            this.logger.error(`Failed to change the key to "${newKeyId}" for config "${this.configFileLocation}": ${error.message}`);

            throw new Error(`Failed to change the key for ${this.configFileLocation}`);
        }
        return true;
    }

    public async readStorage(): Promise<Record<string, string>> {
        if (!this.config) {
            await loadConfig(this);
        }
        return Promise.resolve(this.config);
    }

    public saveStorage(updatedConfig: Record<string, string>): Promise<void> {
        return saveConfig(this, updatedConfig);
    }

    public async get(key: string): Promise<string> {
        const config = await this.readStorage();
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

        if (config[key]) {
            this.logger.debug(`Deleting key ${key} from ${this.configFileLocation}`);
            delete config[key];
        } else {
            this.logger.debug(`Key ${key} not found in ${this.configFileLocation}`);
        }
        await this.saveStorage(config);
    }

    public async deleteAll(): Promise<void> {
        await this.readStorage();
        Object.keys(this.config).forEach(key => delete this.config[key]);
        await this.saveStorage({});
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
