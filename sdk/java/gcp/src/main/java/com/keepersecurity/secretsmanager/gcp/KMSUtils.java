package com.keepersecurity.secretsmanager.gcp;

import java.nio.charset.StandardCharsets;

import com.google.cloud.kms.v1.CryptoKey;
import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.protobuf.ByteString;
import com.google.cloud.kms.v1.GetCryptoKeyRequest;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionState;
import com.google.cloud.kms.v1.DecryptRequest;
import com.google.cloud.kms.v1.EncryptRequest;

public class KMSUtils {

	private KeyManagementServiceClient kmsClient;
	private GcpSessionConfig sessionConfig;

	public KMSUtils(GcpSessionConfig sessionConfig) {
		try {
			// Create the KMS client
			kmsClient = KeyManagementServiceClient.create();
			this.sessionConfig = sessionConfig;
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

//	public void encrypt(String plaintext) {
//		
//		try {
//			// Build the key name from the provided parameters
//			String keyFullName = String.format("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", sessionConfig.getProjectId(),
//					sessionConfig.getLocation(), sessionConfig.getKeyRing(), sessionConfig.getKeyName());
//
//			// Get the crypto key details
//			CryptoKey cryptoKey = kmsClient.getCryptoKey(GetCryptoKeyRequest.newBuilder().setName(keyFullName).build());
//
//			// Fetch the key version (use the primary version of the key)
//			CryptoKeyVersion primaryKeyVersion = cryptoKey.getPrimary();
//			if (primaryKeyVersion != null) {
//				// Determine the algorithm used for the key
//				CryptoKeyVersionAlgorithm algorithm = primaryKeyVersion.getAlgorithm();
//
//				// Output the key type
//				if (algorithm.name().contains("SYMMETRIC")) {
//					ByteString encrypt = encryptSymmetric(kmsClient, keyFullName, plaintext);
//					System.out.println("Encrypted ::" + encrypt.toStringUtf8());
//
//					String decrypt = decryptSymmetric(kmsClient, keyFullName, encrypt);
//					System.out.println("Derypted ::" + decrypt);
//
//				} else {
//					System.out.println("The key is asymmetric.");
//				}
//
//			} else {
//				System.out.println("No primary key version found.");
//			}
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//	}

	public ByteString encryptSymmetric(String plaintext) throws Exception {
		// Create the KMS client

		// Convert plaintext to ByteString
		ByteString plaintextByteString = ByteString.copyFrom(plaintext, StandardCharsets.UTF_8);

		// Encrypt the data
		EncryptRequest encryptRequest = EncryptRequest.newBuilder().setName(getFullName())
				.setPlaintext(plaintextByteString).build();
		ByteString ciphertext = kmsClient.encrypt(encryptRequest).getCiphertext();

		// Return encrypted text as a Base64 string
		return ciphertext;
	}

	public String decryptSymmetric(ByteString ciphertext) throws Exception {

		// Decrypt the data
		DecryptRequest decryptRequest = DecryptRequest.newBuilder().setName(getFullName()).setCiphertext(ciphertext)
				.build();
		ByteString decryptedText = kmsClient.decrypt(decryptRequest).getPlaintext();

		// Convert the decrypted text back to String
		return decryptedText.toStringUtf8();
	}

	public String getFullName() {
		return String.format("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", sessionConfig.getProjectId(),
				sessionConfig.getLocation(), sessionConfig.getKeyRing(), sessionConfig.getKeyName());
	}

	public boolean isSymmetricKey() {

		CryptoKey cryptoKey = kmsClient.getCryptoKey(GetCryptoKeyRequest.newBuilder().setName(getFullName()).build());

		// Fetch the key version (use the primary version of the key)
		CryptoKeyVersion primaryKeyVersion = cryptoKey.getPrimary();
		if (primaryKeyVersion != null) {
			// Determine the algorithm used for the key
			CryptoKeyVersionAlgorithm algorithm = primaryKeyVersion.getAlgorithm();

			// Output the key type
			if (algorithm.name().contains("SYMMETRIC"))
				return true;

			
		}
		return false;

	}
}
