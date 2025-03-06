#nullable enable

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using Azure.Identity;
using SecretsManager;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.Logging;
using System.IO;
using System.Text;
using System.Linq;
using Azure.Core;

namespace AzureKeyVault{

    public class AzureKeyValueStorage : IKeyValueStorage
    {
        private const string DefaultConfigFileLocation = "client-config.json";

        private string keyId;
        private CryptographyClient cryptoClient;
        private  Dictionary<string, string> config = new();
        private string lastSavedConfigHash;
        private readonly string configFileLocation = DefaultConfigFileLocation;
        private readonly ILogger logger;
        public TokenCredential azureCredentials { get; private set; }

        public AzureKeyValueStorage(string keyId,string? configFileLocation = null, AzureSessionConfig? credentials=null,ILogger<AzureKeyValueStorage>? logger = null)
        {
            this.keyId = keyId;
            this.configFileLocation = Path.GetFullPath(configFileLocation) ?? DefaultConfigFileLocation;

            // Initialize Azure Key Vault CryptographyClient
            if (credentials != null && 
                !string.IsNullOrEmpty(credentials.TenantId) && 
                !string.IsNullOrEmpty(credentials.ClientId) && 
                !string.IsNullOrEmpty(credentials.ClientSecret))
            {
                // Use ClientSecretCredential when all values are provided
                azureCredentials = new ClientSecretCredential(
                    credentials.TenantId, 
                    credentials.ClientId, 
                    credentials.ClientSecret);
            }
            else
            {
                // Fallback to DefaultAzureCredential
                azureCredentials = new DefaultAzureCredential();
            }
            cryptoClient = new CryptographyClient(new Uri(keyId), azureCredentials);
            this.logger = logger ?? LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<AzureKeyValueStorage>();
            lastSavedConfigHash = "";
            LoadConfigAsync().Wait();
        }

        public string? GetString(string key)
        {
            return config.TryGetValue(key, out var value) ? value : null;
        }

        public void SaveString(string key, string value)
        {
            config[key] = value;
        }

        public byte[]? GetBytes(string key)
        {
            var stringValue = config.TryGetValue(key, out var result) ? result : null;
            return stringValue == null ? null : CryptoUtils.Base64ToBytes(stringValue);
        }

        public void SaveBytes(string key, byte[] value)
        {
            config[key] = CryptoUtils.BytesToBase64(value);
        }

        public void Delete(string key){
            config.Remove(key);
        }

        public async Task CreateConfigFileIfMissingAsync()
        {
            try
            {
                if (File.Exists(configFileLocation))
                {
                    logger.LogInformation("Config file already exists at: {Path}", configFileLocation);
                    return;
                }

                logger.LogInformation("Config file does not exist at: {Path}", configFileLocation);
                string? directory = Path.GetDirectoryName(configFileLocation);
                if (directory != null && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Encrypt an empty configuration and write to the file
                byte[] blob = await IntegrationUtils.EncryptBufferAsync(cryptoClient,"{}");
                await File.WriteAllBytesAsync(configFileLocation, blob);

                logger.LogInformation("Config file created at: {Path}", configFileLocation);
            }
            catch (Exception ex)
            {
                logger.LogError("Error creating config file: {Message}", ex.Message);
            }
        }

        public async Task LoadConfigAsync()
        {
            await CreateConfigFileIfMissingAsync();

            try
            {
                // Read the config file
                byte[] contents;
                try
                {   
                    string configData = File.ReadAllText(configFileLocation);
                    
                    using (FileStream fs = new FileStream(configFileLocation, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    using (StreamReader reader = new StreamReader(fs))
                    {
                        string json = reader.ReadToEnd();
                        Console.WriteLine($"📜 Read JSON: '{json}' (Length: {json.Length})");
                    }

                    try
                    {
                        bool fileExists = File.Exists(configFileLocation);
                        var obj = JsonSerializer.Deserialize<Dictionary<string, string>>(configData);
                        contents = Encoding.UTF8.GetBytes(configData);
                        Console.WriteLine("Valid JSON parsed successfully.");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error parsing valid JSON: {ex.Message}");
                        contents = await File.ReadAllBytesAsync(configFileLocation);
                    }
                    
                    logger.LogInformation("Loaded config file {Path}", configFileLocation);
                }
                catch (Exception ex)
                {
                    logger.LogError("Failed to load config file {Path}: {Message}", configFileLocation, ex.Message);
                    throw new Exception($"Failed to load config file {configFileLocation}");
                }

                if (contents.Length == 0)
                {
                    logger.LogWarning("Empty config file {Path}", configFileLocation);
                    contents = Encoding.UTF8.GetBytes("{}");
                }

                // Check if the content is plain JSON
                Dictionary<string, string>? parsedConfig = null;
                Exception? jsonError = null;
                bool decryptionError = false;

                try
                {
                    string configData = Encoding.UTF8.GetString(contents);
                    parsedConfig = JsonSerializer.Deserialize<Dictionary<string, string>>(configData);

                    if (parsedConfig != null)
                    {
                        config = parsedConfig;
                        await SaveConfigAsync(config);
                        lastSavedConfigHash = ComputeMD5Hash(SerializeConfig(config));
                        return;
                    }
                }
                catch (Exception ex)
                {
                    jsonError = ex;
                }

                // If parsing as JSON failed, try decryption
                if (jsonError != null)
                {
                    try
                    {
                        string decryptedJson = await IntegrationUtils.DecryptBufferAsync(cryptoClient,contents);
                        parsedConfig = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedJson);

                        if (parsedConfig != null)
                        {
                            config = parsedConfig;
                            lastSavedConfigHash = ComputeMD5Hash(SerializeConfig(config));
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        decryptionError = true;
                        logger.LogError("Failed to parse decrypted config file: {Message}", ex.Message);
                        throw new Exception($"Failed to parse decrypted config file {configFileLocation}");
                    }
                }

                if (jsonError != null && decryptionError)
                {
                    logger.LogError("Config file is not a valid JSON file: {Message}", jsonError.Message);
                    throw new Exception($"{configFileLocation} may contain JSON format problems");
                }
            }
            catch (Exception ex)
            {
                logger.LogError("Error loading config: {Message}", ex.Message);
                throw;
            }
        }

        public async Task SaveConfigAsync(Dictionary<string, string>? updatedConfig = null, bool force = false)
        {
            try
            {
                // Retrieve current config
                Dictionary<string, string> currentConfig = config ?? new();
                string configJson = SerializeConfig(currentConfig);
                string configHash = ComputeMD5Hash(configJson);

                // Compare updatedConfig hash with current config hash
                if (updatedConfig != null && updatedConfig.Count > 0)
                {
                    string updatedConfigJson = SerializeConfig(updatedConfig);
                    string updatedConfigHash = ComputeMD5Hash(updatedConfigJson);

                    if (updatedConfigHash != configHash)
                    {
                        configHash = updatedConfigHash;
                        config = new Dictionary<string, string>(updatedConfig);
                    }
                }

                // Check if saving is necessary
                if (!force && configHash == lastSavedConfigHash)
                {
                    logger.LogWarning("Skipped config JSON save. No changes detected.");
                    return;
                }

                // Ensure the config file exists
                await CreateConfigFileIfMissingAsync();

                // Encrypt the config JSON and write to the file
                byte[] blob = await IntegrationUtils.EncryptBufferAsync(cryptoClient,SerializeConfig(config));
                await File.WriteAllBytesAsync(configFileLocation, blob);

                // Update the last saved config hash
                lastSavedConfigHash = configHash;
            }
            catch (Exception ex)
            {
                logger.LogError("Error saving config: {Message}", ex.Message);
            }
        }

        public async Task<string> DecryptConfigAsync(bool autosave = true)
        {
            byte[] ciphertext;
            string plaintext = "";

            try
            {
                // Read the config file
                if (!File.Exists(configFileLocation))
                {
                    logger.LogError("Config file not found: {File}", configFileLocation);
                    throw new FileNotFoundException($"Config file not found: {configFileLocation}");
                }

                ciphertext = await File.ReadAllBytesAsync(configFileLocation);
                if (ciphertext.Length == 0)
                {
                    logger.LogWarning("Empty config file {File}", configFileLocation);
                    return "";
                }
            }
            catch (Exception ex)
            {
                logger.LogError("Failed to load config file {File}: {Message}", configFileLocation, ex.Message);
                throw new Exception($"Failed to load config file {configFileLocation}");
            }

            try
            {
                // Decrypt the file contents
                plaintext = await IntegrationUtils.DecryptBufferAsync(cryptoClient,ciphertext);
                if (string.IsNullOrWhiteSpace(plaintext))
                {
                    logger.LogError("Failed to decrypt config file {File}", configFileLocation);
                }
                else if (autosave)
                {
                    // Optionally autosave the decrypted content
                    await File.WriteAllTextAsync(configFileLocation, plaintext);
                }
            }
            catch (Exception ex)
            {
                logger.LogError("Failed to write decrypted config file {File}: {Message}", configFileLocation, ex.Message);
                throw new Exception($"Failed to write decrypted config file {configFileLocation}");
            }

            return plaintext;
        }

        public async Task<bool> ChangeKeyAsync(string newKeyId)
        {
            string oldKeyId = keyId;
            CryptographyClient oldCryptoClient = cryptoClient;

            try
            {
                // Update the key and reinitialize the CryptographyClient
                keyId = newKeyId;
                cryptoClient = new CryptographyClient(new Uri(keyId), azureCredentials);

                await SaveConfigAsync(force: true);
            }
            catch (Exception ex)
            {
                // Restore the previous key and crypto client if the operation fails
                keyId = oldKeyId;
                cryptoClient = oldCryptoClient;

                logger.LogError("Failed to change the key to '{NewKeyId}' for config '{ConfigFile}': {Message}", newKeyId, "config.json", ex.Message);
                throw new Exception($"Failed to change the key for config.json");
            }

            return true;
        }

        private static string SerializeConfig(Dictionary<string, string>? config)
        {   
            if (config == null){
                return "{}";
            }
            var sortedKeys = Enumerable.OrderBy(config.Keys, k => k).ToList();
            var sortedConfig = sortedKeys.ToDictionary(k => k, k => config[k]);
            return JsonSerializer.Serialize(sortedConfig, new JsonSerializerOptions { WriteIndented = true });
        }

        private static string ComputeMD5Hash(string input)
        {
            using var md5 = System.Security.Cryptography.MD5.Create();
            byte[] hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }

    }

}