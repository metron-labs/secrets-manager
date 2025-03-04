package com.keepersecurity.secretsmanager.gcp;

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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.protobuf.ByteString;
import com.keepersecurity.secretsManager.core.KeyValueStorage;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class GcpKeyValueStorage implements KeyValueStorage {

	private String defaultConfigFileLocation = "client-config.json";
	private String lastSavedConfigHash, updateConfigHash;
	private String configFileLocation;
	private Map<String, Object> configMap;

	private KMSUtils kmsClient;

	private GcpKeyValueStorage(String configFileLocation, GcpSessionConfig sessionConfig) throws Exception {
		this.configFileLocation = configFileLocation != null ? configFileLocation
				: System.getenv("KSM_CONFIG_FILE") != null ? System.getenv("KSM_CONFIG_FILE")
						: this.defaultConfigFileLocation;
		kmsClient = new KMSUtils(sessionConfig);
		loadConfig();
	}

	/**
	 * 
	 * @param keyId
	 * @param configFileLocation
	 * @param sessionConfig
	 * @return
	 * @throws Exception
	 */
	public static KeyValueStorage getInternalStorage(String configFileLocation, GcpSessionConfig sessionConfig)
			throws Exception {
		KeyValueStorage storage = new GcpKeyValueStorage(configFileLocation, sessionConfig);
		return storage;
	}

	/**
	 * 
	 * @throws Exception
	 */
	private void loadConfig() throws Exception {
		if (!JsonUtil.isValidJsonFile(configFileLocation)) {
			String decryptedContent = decryptBuffer(readEncryptedJsonFile());
			lastSavedConfigHash = calculateMd5(decryptedContent);
			configMap = JsonUtil.convertToMap(decryptedContent);
		} else {
			String configJson = Files.readString(Paths.get(configFileLocation));
			lastSavedConfigHash = calculateMd5(configJson);
			configMap = JsonUtil.convertToMap(configJson);
			saveConfig(configMap);
		}
	}

	private void saveConfig(Map<String, Object> updatedConfig) {
		try {
			if (JsonUtil.isValidJsonFile(configFileLocation)) {
				Path path = Paths.get(configFileLocation);
				save(Files.readString(path), updatedConfig);
			} else {
				String decryptedContent = decryptBuffer(readEncryptedJsonFile());
				save(decryptedContent, updatedConfig);
			}
		} catch (Exception e) {
		}
	}

	private void save(String configJson, Map<String, Object> updatedConfig) {
		if (updatedConfig != null && updatedConfig.size() > 0) {
			try {
				lastSavedConfigHash = calculateMd5(configJson);
				String updatedConfigJson = JsonUtil.convertToString(updatedConfig);
				updateConfigHash = calculateMd5(updatedConfigJson);
				if (updateConfigHash != lastSavedConfigHash) {
					lastSavedConfigHash = updateConfigHash;
					configJson = updatedConfigJson;
					configMap = JsonUtil.convertToMap(configJson);
				}
				byte[] encryptedData = encryptBuffer(configJson);
				Files.write(Paths.get(configFileLocation), encryptedData);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private byte[] readEncryptedJsonFile() throws Exception {
		Path path = Paths.get(configFileLocation);
		if (!Files.exists(path)) {
			createConfigFileIfMissing();
		}
		return Files.readAllBytes(path);

	}

	/**
	 * 
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
	 * 
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
	private Cipher getGCMCipher(int mode, byte[] iv, byte[] key) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException {

		Cipher cipher = Cipher.getInstance(Constants.AES_GCM);
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(Constants.GCM_TAG_LENGTH, iv);
		SecretKeySpec keySpec = new SecretKeySpec(key, Constants.AES);
		cipher.init(mode, keySpec, gcmParameterSpec);
		return cipher;
	}

	private byte[] encryptBuffer(String message) throws Exception {
		if (kmsClient.isSymmetricKey()) {
			byte[] encrypted = kmsClient.encryptSymmetric(message).toByteArray();
			ByteArrayOutputStream blob = new ByteArrayOutputStream();
			writeLengthPrefixed(blob, encrypted);
			return blob.toByteArray();
		} else {
			byte[] nonce = new byte[Constants.BLOCK_SIZE];
			byte[] key = new byte[Constants.KEY_SIZE];
			Cipher cipher = getGCMCipher(Cipher.ENCRYPT_MODE, key, nonce);
			byte[] ciphertext = cipher.doFinal(message.getBytes());

			byte[] tag = cipher.getIV();
			byte[] encryptedKey = kmsClient.encryptAsymmetricRsa(key);

			ByteArrayOutputStream blob = new ByteArrayOutputStream();
			blob.write(Constants.BLOB_HEADER);
			writeLengthPrefixed(blob, encryptedKey);
			writeLengthPrefixed(blob, nonce);
			writeLengthPrefixed(blob, tag);
			writeLengthPrefixed(blob, ciphertext);
			return blob.toByteArray();
		}
	}

	/**
	 * 
	 * @param encryptedData
	 * @return
	 * @throws Exception
	 */
	private String decryptBuffer(byte[] encryptedData) throws Exception {
		if (kmsClient.isSymmetricKey()) {
			ByteArrayInputStream blobInputStream = new ByteArrayInputStream(encryptedData);
			byte[] encrypted = readLengthPrefixed(blobInputStream);
			return kmsClient.decryptSymmetric(ByteString.copyFrom(encrypted));

		} else {
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
			byte[] key = kmsClient.decryptAsymmetricRsa(encryptedKey);

			Cipher cipher = getGCMCipher(Cipher.DECRYPT_MODE, key, nonce);

			byte[] decryptedMessage = cipher.doFinal(ciphertext);
			return new String(decryptedMessage, StandardCharsets.UTF_8);
		}
	}

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

	private String calculateMd5(String input) throws Exception {
		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
		return Base64.getEncoder().encodeToString(digest);
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
			return JsonUtil.convertToString(configMap);
		} catch (JsonProcessingException e) {
		}
		return null;

	}

}