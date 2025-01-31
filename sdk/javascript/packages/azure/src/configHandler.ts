import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { AzureKeyValueStorage } from "./AzureKeyValueStorage";
import { decryptBuffer, encryptBuffer, isJson } from "./utils";
import { dirname } from "path";
import { createHash } from "crypto";


export async function loadConfig(azureKeyValueStorage: AzureKeyValueStorage): Promise<void> {
        await createConfigFileIfMissing(azureKeyValueStorage);

        try {
            // Step 1: Read the config file
            let contents: Buffer = Buffer.alloc(0);
            try {
                contents = readFileSync(azureKeyValueStorage.defaultConfigFileLocation);
                azureKeyValueStorage.logger.info(`Loaded config file ${azureKeyValueStorage.defaultConfigFileLocation}`);
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
            } catch (err: any) {
                azureKeyValueStorage.logger.error(`Failed to load config file ${azureKeyValueStorage.defaultConfigFileLocation}: ${err.message}`);
                throw new Error(`Failed to load config file ${azureKeyValueStorage.defaultConfigFileLocation}`);
            }

            if (contents.length === 0) {
                azureKeyValueStorage.logger.warn(`Empty config file ${azureKeyValueStorage.defaultConfigFileLocation}`);
            }

            // Step 2: Check if the content is plain JSON
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            let config: Record<string, any> | null = null;
            if (isJson(contents)) {
                try {
                    const configData = contents.toString();
                    config = JSON.parse(configData);
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                } catch (err: any) {
                    azureKeyValueStorage.logger.error(`Config file is not a valid JSON file: ${err.message}`);
                    throw new Error(`${azureKeyValueStorage.defaultConfigFileLocation} may contain JSON format problems`);
                }

                // Encrypt and save the config if it's plain JSON
                if (config) {
                    azureKeyValueStorage.config = config;
                    await saveConfig(azureKeyValueStorage,config);
                    azureKeyValueStorage.lastSavedConfigHash = createHash('md5').update(JSON.stringify(config, null, 4)).digest('hex');
                }
            } else {
                // Step 3: Attempt to decrypt the binary blob
                const configJson = await decryptBuffer(azureKeyValueStorage, contents);
                try {
                    config = JSON.parse(configJson);
                    azureKeyValueStorage.config = config ?? {};
                    azureKeyValueStorage.lastSavedConfigHash = createHash('md5').update(JSON.stringify(config, null, 4)).digest('hex');
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                } catch (err: any) {
                    azureKeyValueStorage.logger.error(`Failed to parse decrypted config file: ${err.message}`);
                    throw new Error(`Failed to parse decrypted config file ${azureKeyValueStorage.defaultConfigFileLocation}`);
                }
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            azureKeyValueStorage.logger.error(`Error loading config: ${err.message}`);
            throw err;
        }
    }

export async function saveConfig(
        azureKeyValueStorage: AzureKeyValueStorage,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        updatedConfig: Record<string, any> = {},
        force = false
    ): Promise<void> {
        try {
            // Step 1: Retrieve current config
            const config = azureKeyValueStorage.config || {};
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
                    azureKeyValueStorage.config = { ...updatedConfig }; // Update the current config
                }
            }

            // Step 3: Check if saving is necessary
            if (!force && configHash === azureKeyValueStorage.lastSavedConfigHash) {
                console.warn("Skipped config JSON save. No changes detected.");
                return;
            }

            // Step 4: Ensure the config file exists
            await createConfigFileIfMissing(azureKeyValueStorage);

            // Step 5: Encrypt the config JSON and write to the file
            const blob = await encryptBuffer(azureKeyValueStorage, JSON.stringify(azureKeyValueStorage.config, null, 4));
            writeFileSync(azureKeyValueStorage.defaultConfigFileLocation, blob);

            // Step 6: Update the last saved config hash
            azureKeyValueStorage.lastSavedConfigHash = configHash;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            console.error("Error saving config:", err.message);
        }
    }

export async function decryptConfig( azureKeyValueStorage: AzureKeyValueStorage, autosave: boolean = true): Promise<string> {
        let ciphertext: Buffer = Buffer.alloc(0);
        let plaintext: string = "";

        try {
            // Step 1: Read the config file
            ciphertext = readFileSync(azureKeyValueStorage.defaultConfigFileLocation);
            if (ciphertext.length === 0) {
                azureKeyValueStorage.logger.warn(`Empty config file ${azureKeyValueStorage.defaultConfigFileLocation}`);
                return "";
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            azureKeyValueStorage.logger.error(`Failed to load config file ${azureKeyValueStorage.defaultConfigFileLocation}: ${err.message}`);
            throw new Error(`Failed to load config file ${azureKeyValueStorage.defaultConfigFileLocation}`);
        }

        try {
            // Step 2: Decrypt the file contents
            plaintext = await decryptBuffer(azureKeyValueStorage, ciphertext);
            if (plaintext.length === 0) {
                azureKeyValueStorage.logger.error(`Failed to decrypt config file ${azureKeyValueStorage.defaultConfigFileLocation}`);
            } else if (autosave) {
                // Step 3: Optionally autosave the decrypted content
                writeFileSync(azureKeyValueStorage.defaultConfigFileLocation, plaintext);
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            azureKeyValueStorage.logger.error(`Failed to write decrypted config file ${azureKeyValueStorage.defaultConfigFileLocation}: ${err.message}`);
            throw new Error(`Failed to write decrypted config file ${azureKeyValueStorage.defaultConfigFileLocation}`);
        }

        return plaintext;
    }

export async function createConfigFileIfMissing(azureKeyValueStorage: AzureKeyValueStorage): Promise<void> {
        try {
            // Check if the config file already exists
            if (!existsSync(azureKeyValueStorage.defaultConfigFileLocation)) {
                // Ensure the directory structure exists
                const dir = dirname(azureKeyValueStorage.defaultConfigFileLocation);
                if (!existsSync(dir)) {
                    mkdirSync(dir, { recursive: true });
                }

                // Encrypt an empty configuration and write to the file
                const blob = await encryptBuffer(azureKeyValueStorage,"{}");
                writeFileSync(azureKeyValueStorage.defaultConfigFileLocation, blob);
                console.log("Config file created at:", azureKeyValueStorage.defaultConfigFileLocation);
            } else {
                console.log("Config file already exists at:", azureKeyValueStorage.defaultConfigFileLocation);
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            console.error("Error creating config file:", err.message);
        }
    }
