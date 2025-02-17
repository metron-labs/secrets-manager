import { promises as fs } from "fs";
import { dirname } from "path";
import { createHash } from "crypto";

import {
  KeyValueStorage,
  platform,
} from "@keeper-security/secrets-manager-core";

import { GCPKeyConfig } from "./GcpKeyConfig";
import { GCPKeyValueStorageError } from "./error";
import { GCPKSMClient } from "./GcpKmsClient";
import { KeyPurpose } from "./enum";
import {
  DEFAULT_JSON_INDENT,
  HEX_DIGEST,
  MD5_HASH,
  supportedKeyPurpose,
} from "./constants";
import { decryptBuffer, encryptBuffer } from "./utils";
import { defaultLogger, Logger } from "./Logger";
import { KMSClient } from "./interface/UtilOptions";

export class GCPKeyValueStorage implements KeyValueStorage {
  defaultConfigFileLocation: string = "client-config.json";
  cryptoClient!: KMSClient;
  config: Record<string, string> = {};
  lastSavedConfigHash!: string;
  logger: Logger;
  gcpKeyConfig!: GCPKeyConfig;
  keyType: string;
  configFileLocation!: string;
  gcpSessionConfig: GCPKSMClient;
  isAsymmetric: boolean = false;

  setLogger(logger: Logger | null) {
    if (logger) {
      this.logger = logger;
    } else {
      this.logger = defaultLogger;
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
    return this.getString(key).then((value) =>
      value ? (JSON.parse(value) as T) : undefined
    );
  }

  saveObject?<T>(key: string, value: T): Promise<void> {
    const json = JSON.stringify(value);
    return this.saveString(key, json);
  }

  /**
   * Initializes GCPKeyValueStorage
   *
   * @param {string | null} keyVaultConfigFileLocation Custom config file location.
   *    If null or undefined, reads from env KSM_CONFIG_FILE.
   *    If env KSM_CONFIG_FILE is not set, uses default location.
   * @param {GCPKeyConfig} gcpKeyConfig The configuration for the GCP KMS key.
   * @param {GCPKSMClient} gcpSessionConfig The GCP KMS client session configuration.
   * @param {Logger | null} logger The logger instance. If null or undefined, uses the default logger.
   */
  constructor(
    keyVaultConfigFileLocation: string | null,
    gcpKeyConfig: GCPKeyConfig,
    gcpSessionConfig: GCPKSMClient,
    logger: Logger | null
  ) {
    this.configFileLocation =
      keyVaultConfigFileLocation ??
      process.env.KSM_CONFIG_FILE ??
      this.defaultConfigFileLocation;
    this.setLogger(logger);

    this.gcpSessionConfig = gcpSessionConfig;
    this.gcpKeyConfig = gcpKeyConfig;
    this.cryptoClient = this.gcpSessionConfig.getCryptoClient();

    this.lastSavedConfigHash = "";
  }

  async init() {
    await this.getKeyDetails();
    await this.loadConfig();
    this.logger.info(`Loaded config file from ${this.configFileLocation}`);
    return this; // Return the instance to allow chaining
  }

  async getKeyDetails() {
    try {
      const input = {
        name: this.gcpKeyConfig.toKeyName(),
      };
      const [key] = await this.cryptoClient.getCryptoKey(input);
      const keyPurposeDetails = key.purpose.toString();

      if (!supportedKeyPurpose.includes(keyPurposeDetails)) {
        this.logger.error("Unsupported Key Spec for GCP KMS Storage");
        throw new GCPKeyValueStorageError(
          "Unsupported Key Spec for GCP KMS Storage"
        );
      }

      if (keyPurposeDetails === KeyPurpose.ASYMMETRIC_DECRYPT) {
        this.isAsymmetric = true;
      } else {
        this.isAsymmetric = false;
      }

      this.keyType = keyPurposeDetails;
      //eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      this.logger.error("Failed to get key details:", err.message);
    }
  }

  private async loadConfig(): Promise<void> {
    await this.createConfigFileIfMissing();

    try {
      // Read the config file
      let contents: Buffer;
      try {
        contents = await fs.readFile(this.configFileLocation);
        this.logger.info(`Loaded config file ${this.configFileLocation}`);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } catch (err: any) {
        this.logger.error(
          `Failed to load config file ${this.configFileLocation}: ${err.message}`
        );
        throw new Error(
          `Failed to load config file ${this.configFileLocation}`
        );
      }

      if (contents.length === 0) {
        this.logger.warn(`Empty config file ${this.configFileLocation}`);
        contents = Buffer.from("{}");
      }

      // Check if the content is plain JSON
      let config: Record<string, string> | null = null;
      let jsonError;
      let decryptionError = false;
      try {
        const configData = contents.toString();
        config = JSON.parse(configData);
        // Encrypt and save the config if it's plain JSON
        if (config) {
          this.config = config;
          await this.saveConfig(config);
          this.lastSavedConfigHash = createHash(MD5_HASH)
            .update(
              JSON.stringify(
                config,
                Object.keys(config).sort(),
                DEFAULT_JSON_INDENT
              )
            )
            .digest(HEX_DIGEST);
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } catch (err: any) {
        jsonError = err;
      }

      if (jsonError) {
        const configJson = await decryptBuffer({
          isAsymmetric: this.isAsymmetric,
          ciphertext: contents,
          cryptoClient: this.cryptoClient,
          keyType: this.keyType,
          keyProperties: this.gcpKeyConfig
        });
        try {
          config = JSON.parse(configJson);
          this.config = config ?? {};
          this.lastSavedConfigHash = createHash(MD5_HASH)
            .update(
              JSON.stringify(
                config,
                Object.keys(this.config).sort(),
                DEFAULT_JSON_INDENT
              )
            )
            .digest(HEX_DIGEST);
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
          decryptionError = true;
          this.logger.error(
            `Failed to parse decrypted config file: ${err.message}`
          );
          throw new Error(
            `Failed to parse decrypted config file ${this.configFileLocation}`
          );
        }
      }
      if (jsonError && decryptionError) {
        this.logger.info(
          `Config file is not a valid JSON file: ${jsonError.message}`
        );
        throw new Error(
          `${this.configFileLocation} may contain JSON format problems`
        );
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      this.logger.error(`Error loading config: ${err.message}`);
      throw err;
    }
  }

  private async saveConfig(
    updatedConfig: Record<string, string> = {},
    force = false
  ): Promise<void> {
    try {
      // Retrieve current config
      const config = this.config || {};
      const configJson = JSON.stringify(
        config,
        Object.keys(config).sort(),
        DEFAULT_JSON_INDENT
      );
      let configHash = createHash(MD5_HASH)
        .update(configJson)
        .digest(HEX_DIGEST);

      // Compare updatedConfig hash with current config hash
      if (Object.keys(updatedConfig).length > 0) {
        const updatedConfigJson = JSON.stringify(
          updatedConfig,
          Object.keys(updatedConfig).sort(),
          DEFAULT_JSON_INDENT
        );
        const updatedConfigHash = createHash(MD5_HASH)
          .update(updatedConfigJson)
          .digest(HEX_DIGEST);

        if (updatedConfigHash !== configHash) {
          configHash = updatedConfigHash;
          this.config = { ...updatedConfig }; // Update the current config
        }
      }

      // Check if saving is necessary
      if (!force && configHash === this.lastSavedConfigHash) {
        console.warn("Skipped config JSON save. No changes detected.");
        return;
      }

      // Ensure the config file exists
      await this.createConfigFileIfMissing();

      // Encrypt the config JSON and write to the file
      const stringifiedValue = JSON.stringify(
        this.config,
        Object.keys(this.config),
        DEFAULT_JSON_INDENT
      );
      const blob = await encryptBuffer({
        isAsymmetric: this.isAsymmetric,
        message: stringifiedValue,
        cryptoClient: this.cryptoClient,
        keyType: this.keyType,
        keyProperties: this.gcpKeyConfig
      });
      await fs.writeFile(this.configFileLocation, blob);

      // Update the last saved config hash
      this.lastSavedConfigHash = configHash;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      console.error("Error saving config:", err.message);
    }
  }

  public async decryptConfig(autosave: boolean = true): Promise<string> {
    let ciphertext: Buffer;
    let plaintext: string = "";

    try {
      // Read the config file
      ciphertext = await fs.readFile(this.configFileLocation);
      if (ciphertext.length === 0) {
        this.logger.warn(`Empty config file ${this.configFileLocation}`);
        return "";
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      this.logger.error(
        `Failed to load config file ${this.configFileLocation}: ${err.message}`
      );
      throw new Error(`Failed to load config file ${this.configFileLocation}`);
    }

    try {
      // Decrypt the file contents
      plaintext = await decryptBuffer({
        isAsymmetric: this.isAsymmetric,
        cryptoClient: this.cryptoClient,
        keyType: this.keyType,
        keyProperties: this.gcpKeyConfig,
        ciphertext,
      });
      if (plaintext.length === 0) {
        this.logger.error(
          `Failed to decrypt config file ${this.configFileLocation}`
        );
      } else if (autosave) {
        // Optionally autosave the decrypted content
        await fs.writeFile(this.configFileLocation, plaintext);
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      this.logger.error(
        `Failed to write decrypted config file ${this.configFileLocation}: ${err.message}`
      );
      throw new Error(
        `Failed to write decrypted config file ${this.configFileLocation}`
      );
    }

    return plaintext;
  }

  public async changeKey(newGcpKeyConfig: GCPKeyConfig): Promise<boolean> {
    const oldKeyConfiguration = this.gcpKeyConfig;
    const oldCryptoClient = this.cryptoClient;

    try {
      // Update the key and reinitialize the CryptographyClient
      const config = this.config;
      if (Object.keys(config).length == 0) {
        await this.init();
      }
      this.gcpKeyConfig = newGcpKeyConfig;
      await this.getKeyDetails();
      await this.saveConfig({}, true);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (error: any) {
      // Restore the previous key and crypto client if the operation fails
      this.gcpKeyConfig = oldKeyConfiguration;
      this.cryptoClient = oldCryptoClient;
      this.logger.error(
        `Failed to change the key to '${newGcpKeyConfig.toString()}' for config '${this.configFileLocation}': ${error.message}`
      );
      throw new Error(
        `Failed to change the key for ${this.configFileLocation}`
      );
    }
    return true;
  }

  private async createConfigFileIfMissing(): Promise<void> {
    try {
      // Check if the config file already exists
      if (await !fs.access(this.configFileLocation)) {
        // Ensure the directory structure exists
        const dir = dirname(this.configFileLocation);
        if (await !fs.access(dir)) {
          fs.mkdir(dir, { recursive: true });
        }

        // Encrypt an empty configuration and write to the file
        const blob = await encryptBuffer({
          isAsymmetric: this.isAsymmetric,
          message: "{}",
          keyType: this.keyType,
          cryptoClient: this.cryptoClient,
          keyProperties: this.gcpKeyConfig
        });
        await fs.writeFile(this.configFileLocation, blob);
        console.log("Config file created at:", this.configFileLocation);
      } else {
        console.log("Config file already exists at:", this.configFileLocation);
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      console.error("Error creating config file:", err.message);
    }
  }

  public async readStorage(): Promise<Record<string, string>> {
    if (!this.config) {
      await this.loadConfig();
    }
    return Promise.resolve(this.config);
  }

  public saveStorage(updatedConfig: Record<string, string>): Promise<void> {
    return this.saveConfig(updatedConfig);
  }

  public async get(key: string): Promise<string> {
    const config = await this.readStorage();
    return Promise.resolve(config[key]);
  }

  public async set(key: string, value: string): Promise<void> {
    const config = await this.readStorage();
    config[key] = value;
    await this.saveStorage(config);
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
    Object.keys(this.config).forEach((key) => delete this.config[key]);
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
