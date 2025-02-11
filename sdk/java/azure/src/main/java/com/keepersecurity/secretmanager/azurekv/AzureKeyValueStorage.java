package com.keepersecurity.secretmanager.azurekv;

import com.azure.core.credential.TokenCredential;
import com.azure.core.util.logging.ClientLogger;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.UnwrapResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.keepersecurity.secretsManager.core.KeyValueStorage;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com
**/


public class AzureKeyValueStorage implements KeyValueStorage{

	private String defaultConfigFileLocation = "client-config.json";
	public KeyClient keyClient;
	public String keyId;
	private CryptographyClient cryptoClient;
	private TokenCredential tokencredential;
	private String lastSavedConfigHash, updateConfigHash;
	private String configFileLocation;
	Map<String, Object> configMap;

	private static final ClientLogger LOGGER = new ClientLogger(AzureKeyValueStorage.class);
	
	private AzureKeyValueStorage() {}

	private AzureKeyValueStorage(String keyId, String configFileLocation, AzureSessionConfig azSessionConfig)
			throws Exception {
		this.configFileLocation = configFileLocation != null ? configFileLocation
				: System.getenv(Constants.KSM_CONFIG_FILE) != null ? System.getenv(Constants.KSM_CONFIG_FILE)
						: this.defaultConfigFileLocation;
		this.keyId = keyId != null ? keyId : System.getenv(Constants.KSM_AZ_KEY_ID);
		tokencredential = getSecretCredential(azSessionConfig);
		cryptoClient = new CryptographyClientBuilder().credential(tokencredential).keyIdentifier(keyId).buildClient();
		loadConfig();
	}

	public static KeyValueStorage getInternalStorage(String keyId, String configFileLocation,
			AzureSessionConfig azSessionConfig) throws Exception {
		KeyValueStorage storage = new AzureKeyValueStorage(keyId, configFileLocation, azSessionConfig);
		return storage;
	}

	/**
	 * 
	 * @param azSessionConfig
	 * @return
	 */
	private static TokenCredential getSecretCredential(AzureSessionConfig azSessionConfig) {
		return new ClientSecretCredentialBuilder().clientId(azSessionConfig.getClientId())
				.clientSecret(azSessionConfig.getClientSecret()).tenantId(azSessionConfig.getTenantId()).build();
	}

	/**
	 * Load the configuration for encrypt/decrypt
	 * @throws Exception
	 */
	private void loadConfig() throws Exception{
		if (!JsonUtils.isValidJsonFile(configFileLocation)) {
			String decryptedContent = decryptBuffer(readEncryptedJsonFile());
				lastSavedConfigHash = calculateMd5(decryptedContent);
				configMap = JsonUtils.convertToMap(decryptedContent); 
		}else {
			String configJson = Files.readString(Paths.get(configFileLocation));
			lastSavedConfigHash = calculateMd5(configJson);
            configMap = JsonUtils.convertToMap(configJson);  
			saveConfig(configMap);
		}
	}
	
	/**
	 * Save configuration encrypted configuration
	 * @param updatedConfig
	 */
	private void saveConfig(Map<String, Object> updatedConfig) {
		try {
			if (JsonUtils.isValidJsonFile(configFileLocation)) {
				Path path = Paths.get(configFileLocation);
				save(Files.readString(path), updatedConfig);
			}else {
				String decryptedContent = decryptBuffer(readEncryptedJsonFile());
				save(decryptedContent, updatedConfig);
				
			}
		} catch (Exception e) {
			LOGGER.error(e.getMessage());
		}
	}
	
	private void save(String configJson, Map<String, Object> updatedConfig) {
		if (updatedConfig != null && updatedConfig.size() > 0) {
			try {
				lastSavedConfigHash = calculateMd5(configJson);
				String updatedConfigJson = JsonUtils.convertToString(updatedConfig);
				updateConfigHash = calculateMd5(updatedConfigJson);
				if (updateConfigHash != lastSavedConfigHash) {
					lastSavedConfigHash = updateConfigHash;
					configJson = updatedConfigJson;
					configMap = JsonUtils.convertToMap(configJson); 
				}
				byte[] encryptedData = encryptBuffer(configJson);
				Files.write(Paths.get(configFileLocation), encryptedData);
			} catch (Exception e) {

			}
		}
	}
	private byte[] readEncryptedJsonFile() throws Exception{
		Path path = Paths.get(configFileLocation);
		if (!Files.exists(path)) {
			createConfigFileIfMissing();
		}
		return Files.readAllBytes(path);
		
	}

	/**
	 * Write the encrypted configuration with key into file
	 * @param stream
	 * @param data
	 * @throws IOException
	 */
	private void writeLengthPrefixed(ByteArrayOutputStream stream, byte[] data) throws IOException {
		stream.write((data.length >> 8) & 0xFF);
		stream.write(data.length & 0xFF);
		stream.write(data);
	}

	/**
	 * Generate GCM Cipher
	 * @param mode
	 * @param iv
	 * @param key
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 */
	private Cipher getGCMCipher(int mode, byte[] iv, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException {
		
		Cipher cipher = Cipher.getInstance(Constants.AES_GCM);
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(Constants.GCM_TAG_LENGTH, iv);
		SecretKeySpec keySpec = new SecretKeySpec(key, Constants.AES);
		cipher.init(mode, keySpec, gcmParameterSpec);
		return cipher;
	}
	
	/**
	 * Encrypt the configuration
	 * @param message
	 * @return
	 * @throws Exception
	 */
	private byte[] encryptBuffer(String message) throws Exception {

		byte[] nance = new byte[Constants.BLOCK_SIZE];
		byte[] key = new byte[Constants.KEY_SIZE];
		Cipher cipher = getGCMCipher(Cipher.ENCRYPT_MODE, key, nance);
		byte[] ciphertext = cipher.doFinal(message.getBytes());
		
		byte[] tag = cipher.getIV();
		byte[] encryptedKey = cryptoClient.wrapKey(KeyWrapAlgorithm.RSA_OAEP, key).getEncryptedKey();

		ByteArrayOutputStream blob = new ByteArrayOutputStream();
		blob.write(Constants.BLOB_HEADER);
		writeLengthPrefixed(blob, encryptedKey);
		writeLengthPrefixed(blob, nance);
		writeLengthPrefixed(blob, tag);
		writeLengthPrefixed(blob, ciphertext);
		return blob.toByteArray();
	}
	/**
	 * Decrypt the configuration
	 * @param encryptedData
	 * @return
	 * @throws Exception
	 */
	private String decryptBuffer(byte[] encryptedData) throws Exception {
		ByteArrayInputStream blobInputStream = new ByteArrayInputStream(encryptedData);

		byte[] header = new byte[Constants.BLOB_HEADER.length];
		blobInputStream.read(header);
		if (!MessageDigest.isEqual(header, Constants.BLOB_HEADER)) {
			throw new IllegalArgumentException("Invalid blob header");
		}
		byte[] encryptedKey = readLengthPrefixed(blobInputStream);
		byte[] nonce = readLengthPrefixed(blobInputStream);
		byte[] tag = readLengthPrefixed(blobInputStream);
		byte[] ciphertext = readLengthPrefixed(blobInputStream);

		// Decrypt the AES key using RSA (unwrap the key)
		UnwrapResult unwrapResult = cryptoClient.unwrapKey(KeyWrapAlgorithm.RSA_OAEP, encryptedKey);
		byte[] key = unwrapResult.getKey();
		
		Cipher cipher = getGCMCipher(Cipher.DECRYPT_MODE, key, nonce);
		
		byte[] decryptedMessage = cipher.doFinal(ciphertext);
		return new String(decryptedMessage, StandardCharsets.UTF_8);
	}

	/**
	 * 
	 * @param stream
	 * @return
	 * @throws IOException
	 */
	private byte[] readLengthPrefixed(InputStream stream) throws IOException {
		int length = (stream.read() << 8) | stream.read();
		byte[] data = new byte[length];
		stream.read(data);
		return data;
	}

	/**
	 * 
	 * @throws Exception
	 */
	private void createConfigFileIfMissing() throws Exception {
		Path path = Paths.get(configFileLocation);
		if (!Files.exists(path)) {
			Files.write(path, encryptBuffer("{}"));
		}
	}

	/**
	 * 
	 * @param input
	 * @return
	 * @throws Exception
	 */
	private String calculateMd5(String input) throws Exception {
		if (JsonUtils.isValidJson(input)) {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(digest);
		} else
			return input;
	}

	@Override
	public void delete(String key) {
		configMap.remove(key);
		saveConfig(configMap);
	}

	@Override
	public byte[] getBytes(String key) {
		return configMap.get(key).toString().getBytes();
	}

	@Override
	public String getString(String key) {
		return configMap.get(key).toString();
	}

	@Override
	public void saveBytes(String key, byte[] value) {
		configMap.put(key, new String(value, StandardCharsets.UTF_8));
		saveConfig(configMap);
		
	}

	@Override
	public void saveString(String key, String value) {
		configMap.put(key, value);
		saveConfig(configMap);
	}

	@Override
	public String toString() {
		try {
			return JsonUtils.convertToString(configMap); 
		} catch (JsonProcessingException e) {
			LOGGER.error(e.getMessage());
		}
		return null;

	}
}
