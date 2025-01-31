import { promises as fs } from "fs";
import { AzureKeyValueStorage } from "./AzureKeyValueStorage";
import { decryptBuffer, encryptBuffer } from "./utils";
import { dirname } from "path";
import { createHash } from "crypto";

export async function loadConfig(azureKeyValueStorage: AzureKeyValueStorage): Promise<void> {
    await createConfigFileIfMissing(azureKeyValueStorage);
    try {
        // Read the config file
        const contents: Buffer = await readContentsFromFile(azureKeyValueStorage);
        // Check if the content is plain JSON
        await checkContentsAndComputeHash(contents, azureKeyValueStorage);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        azureKeyValueStorage.logger.error(`Error loading config: ${err.message}`);
        throw err;
    }
}

export async function saveConfig(
    azureKeyValueStorage: AzureKeyValueStorage,
    updatedConfig: Record<string, string> = {},
    force = false
): Promise<void> {
    try {
        // Retrieve current config and compute hash
        const configHash = updateCurrentConfigHash(azureKeyValueStorage, updatedConfig);
        // Check if saving is necessary
        if (!force && configHash === azureKeyValueStorage.lastSavedConfigHash) {
            console.warn("Skipped config JSON save. No changes detected.");
            return;
        }
        // Ensure the config file exists
        await createConfigFileIfMissing(azureKeyValueStorage);
        // Encrypt the config JSON and write to the file
        const blob = await encryptBuffer(azureKeyValueStorage, JSON.stringify(azureKeyValueStorage.config, null, 4));
        await fs.writeFile(azureKeyValueStorage.configFileLocation, blob);
        // Update the last saved config hash
        azureKeyValueStorage.lastSavedConfigHash = configHash;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        console.error("Error saving config:", err.message);
    }
}

export async function decryptConfig(azureKeyValueStorage: AzureKeyValueStorage, autosave: boolean = true): Promise<string> {
    let ciphertext: Buffer = Buffer.alloc(0);
    let plaintext: string = "";

    try {
        // Read the config file
        ciphertext = await fs.readFile(azureKeyValueStorage.configFileLocation);
        if (ciphertext.length === 0) {
            azureKeyValueStorage.logger.warn(`Empty config file ${azureKeyValueStorage.configFileLocation}`);
            return "";
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        azureKeyValueStorage.logger.error(`Failed to load config file ${azureKeyValueStorage.configFileLocation}: ${err.message}`);
        throw new Error(`Failed to load config file ${azureKeyValueStorage.configFileLocation}`);
    }

    try {
        // Decrypt the file contents
        plaintext = await decryptBuffer(azureKeyValueStorage, ciphertext);
        if (plaintext.length === 0) {
            azureKeyValueStorage.logger.error(`Failed to decrypt config file ${azureKeyValueStorage.configFileLocation}`);
        } else if (autosave) {
            // Optionally autosave the decrypted content
            await fs.writeFile(azureKeyValueStorage.configFileLocation, plaintext);
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        azureKeyValueStorage.logger.error(`Failed to write decrypted config file ${azureKeyValueStorage.configFileLocation}: ${err.message}`);
        throw new Error(`Failed to write decrypted config file ${azureKeyValueStorage.configFileLocation}`);
    }

    return plaintext;
}

export async function createConfigFileIfMissing(azureKeyValueStorage: AzureKeyValueStorage): Promise<void> {
    try {
        // Check if the config file already exists
        if (await !fs.access(azureKeyValueStorage.configFileLocation)) {
            // Ensure the directory structure exists
            const dir = dirname(azureKeyValueStorage.configFileLocation);
            if (await !fs.access(dir)) {
                await fs.mkdir(dir, { recursive: true });
            }
            // Encrypt an empty configuration and write to the file
            const blob = await encryptBuffer(azureKeyValueStorage, "{}");
            await fs.writeFile(azureKeyValueStorage.configFileLocation, blob);
            console.log("Config file created at:", azureKeyValueStorage.configFileLocation);
        } else {
            console.log("Config file already exists at:", azureKeyValueStorage.configFileLocation);
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        console.error("Error creating config file:", err.message);
    }
}


async function readContentsFromFile(azureKeyValueStorage: AzureKeyValueStorage): Promise<Buffer> {
    let contents: Buffer = Buffer.alloc(0);
    try {
        contents = await fs.readFile(azureKeyValueStorage.configFileLocation);
        azureKeyValueStorage.logger.info(`Loaded config file ${azureKeyValueStorage.configFileLocation}`);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        azureKeyValueStorage.logger.error(`Failed to load config file ${azureKeyValueStorage.configFileLocation}: ${err.message}`);
        throw new Error(`Failed to load config file ${azureKeyValueStorage.configFileLocation}`);
    }

    if (contents.length === 0) {
        azureKeyValueStorage.logger.warn(`Empty config file ${azureKeyValueStorage.configFileLocation}`);
    }
    return contents;
}

async function checkContentsAndComputeHash(contents: Buffer, azureKeyValueStorage: AzureKeyValueStorage): Promise<void> {
    let config: Record<string, string> | null = null;
    try {
        const configData = contents.toString();
        // Attempt to parse as JSON first
        config = JSON.parse(configData);
        azureKeyValueStorage.config = config;
        // Encrypt and save the config if it was plain JSON
        await saveConfig(azureKeyValueStorage, config);
    } catch {
        try {
            // If parsing failed, assume it's encrypted and attempt decryption
            const configJson = await decryptBuffer(azureKeyValueStorage, contents);
            config = JSON.parse(configJson);
            azureKeyValueStorage.config = config;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            azureKeyValueStorage.logger.error(`Failed to parse decrypted config file: ${err.message}`);
            throw new Error(`Failed to parse decrypted config file ${azureKeyValueStorage.configFileLocation}`);
        }
    }

    // Compute and store hash
    azureKeyValueStorage.lastSavedConfigHash = createHash("md5")
        .update(JSON.stringify(azureKeyValueStorage.config, null, 4))
        .digest("hex");
}


function updateCurrentConfigHash(azureKeyValueStorage: AzureKeyValueStorage, updatedConfig: Record<string, string>): string {
    // Retrieve current config
    const config = azureKeyValueStorage.config || {};
    const configJson = JSON.stringify(config, null, 4);
    let configHash = createHash("md5").update(configJson).digest("hex");

    // Compare updatedConfig hash with current config hash
    if (Object.keys(updatedConfig).length > 0) {
        const updatedConfigJson = JSON.stringify(updatedConfig, null, 4);
        const updatedConfigHash = createHash("md5")
            .update(updatedConfigJson)
            .digest("hex");
        if (updatedConfigHash !== configHash) {
            configHash = updatedConfigHash;
            azureKeyValueStorage.config = { ...updatedConfig }; // Update the current config
        }
    }
    return configHash;
}