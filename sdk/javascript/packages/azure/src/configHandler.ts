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
        if (!force && configHash === azureKeyValueStorage.getConfigHash()) {
            console.warn("Skipped config JSON save. No changes detected.");
            return;
        }
        // Encrypt the config JSON and write to the file
        await azureKeyValueStorage.writeConfigToFile();
        // Update the last saved config hash
        azureKeyValueStorage.setConfigHash (configHash);
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
        ciphertext = await fs.readFile(azureKeyValueStorage.getConfigFileLocation());
        if (ciphertext.length === 0) {
            azureKeyValueStorage.logger.warn(`Empty config file ${azureKeyValueStorage.getConfigFileLocation()}`);
            return "";
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        azureKeyValueStorage.logger.error(`Failed to load config file ${azureKeyValueStorage.getConfigFileLocation()}: ${err.message}`);
        throw new Error(`Failed to load config file ${azureKeyValueStorage.getConfigFileLocation()}`);
    }

    try {
        // Decrypt the file contents
        plaintext = await decryptBuffer(azureKeyValueStorage.getCryptoClient(), ciphertext);
        if (plaintext.length === 0) {
            azureKeyValueStorage.logger.error(`Failed to decrypt config file ${azureKeyValueStorage.getConfigFileLocation()}`);
        } else if (autosave) {
            // Optionally autosave the decrypted content
            await fs.writeFile(azureKeyValueStorage.getConfigFileLocation(), plaintext);
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        azureKeyValueStorage.logger.error(`Failed to write decrypted config file ${azureKeyValueStorage.getConfigFileLocation()}: ${err.message}`);
        throw new Error(`Failed to write decrypted config file ${azureKeyValueStorage.getConfigFileLocation()}`);
    }

    return plaintext;
}

export async function createConfigFileIfMissing(azureKeyValueStorage: AzureKeyValueStorage): Promise<void> {
    try {
        // Check if the config file already exists
        if (await !fs.access(azureKeyValueStorage.getConfigFileLocation())) {
            // Ensure the directory structure exists
            const dir = dirname(azureKeyValueStorage.getConfigFileLocation());
            if (await !fs.access(dir)) {
                await fs.mkdir(dir, { recursive: true });
            }
            // Encrypt an empty configuration and write to the file
            const blob = await encryptBuffer(azureKeyValueStorage.getCryptoClient(), "{}");
            await fs.writeFile(azureKeyValueStorage.getConfigFileLocation(), blob);
            console.log("Config file created at:", azureKeyValueStorage.getConfigFileLocation());
        } else {
            console.log("Config file already exists at:", azureKeyValueStorage.getConfigFileLocation());
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        console.error("Error creating config file:", err.message);
    }
}


async function readContentsFromFile(azureKeyValueStorage: AzureKeyValueStorage): Promise<Buffer> {
    let contents: Buffer = Buffer.alloc(0);
    try {
        contents = await fs.readFile(azureKeyValueStorage.getConfigFileLocation());
        azureKeyValueStorage.logger.info(`Loaded config file ${azureKeyValueStorage.getConfigFileLocation()}`);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        azureKeyValueStorage.logger.error(`Failed to load config file ${azureKeyValueStorage.getConfigFileLocation()}: ${err.message}`);
        throw new Error(`Failed to load config file ${azureKeyValueStorage.getConfigFileLocation()}`);
    }

    if (contents.length === 0) {
        azureKeyValueStorage.logger.warn(`Empty config file ${azureKeyValueStorage.getConfigFileLocation()}`);
    }
    return contents;
}

async function checkContentsAndComputeHash(contents: Buffer, azureKeyValueStorage: AzureKeyValueStorage): Promise<void> {
    const cryptoClient = azureKeyValueStorage.getCryptoClient();

    let config: Record<string, string> | null = null;
    try {
        const configData = contents.toString();
        // Attempt to parse as JSON first
        config = JSON.parse(configData);
        azureKeyValueStorage.setConfig(config);
        // Encrypt and save the config if it was plain JSON
        await saveConfig(azureKeyValueStorage, config);
    } catch {
        try {
            // If parsing failed, assume it's encrypted and attempt decryption
            const configJson = await decryptBuffer(cryptoClient, contents);
            config = JSON.parse(configJson);
            azureKeyValueStorage.setConfig(config);
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (err: any) {
            azureKeyValueStorage.logger.error(`Failed to parse decrypted config file: ${err.message}`);
            throw new Error(`Failed to parse decrypted config file ${azureKeyValueStorage.getConfigFileLocation()}`);
        }
    }

    // Compute and store hash
    const updatedHash =  createHash("md5")
        .update(JSON.stringify(azureKeyValueStorage.getConfig(), null, 4))
        .digest("hex");
    azureKeyValueStorage.setConfigHash(updatedHash);
}


function updateCurrentConfigHash(azureKeyValueStorage: AzureKeyValueStorage, updatedConfig: Record<string, string>): string {
    // Retrieve current config
    const config = azureKeyValueStorage.getConfig() || {};
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
            azureKeyValueStorage.setConfig(updatedConfig); // Update the current config
        }
    }
    return configHash;
}
