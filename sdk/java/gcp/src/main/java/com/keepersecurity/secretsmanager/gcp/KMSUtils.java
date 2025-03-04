package com.keepersecurity.secretsmanager.gcp;

import java.io.BufferedReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import com.google.cloud.kms.v1.AsymmetricDecryptResponse;
import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.PublicKey;
import com.google.protobuf.ByteString;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.DecryptRequest;
import com.google.cloud.kms.v1.EncryptRequest;

public class KMSUtils {

	private KeyManagementServiceClient kmsClient;
	private GcpSessionConfig sessionConfig;

	private static final Map<String, String> rsaAlgorithmToSHA = new HashMap<>();

    static {
        // Initialize the mapping of algorithms to SHA types
        rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_2048_SHA256", "SHA-256");
        rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_3072_SHA256", "SHA-256");
        rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_4096_SHA256", "SHA-256");
        rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_4096_SHA512", "SHA-512");
        rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_2048_SHA1", "SHA-1");
        rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_3072_SHA1", "SHA-1");
        rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_4096_SHA1", "SHA-1");
    }
    
	public KMSUtils(GcpSessionConfig sessionConfig) {
		try {
			// Create the KMS client
			kmsClient = KeyManagementServiceClient.create();
			this.sessionConfig = sessionConfig;
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Encrypt data using an asymmetric RSA public key
	 * @param text
	 * @return
	 * @throws Exception
	 */
	public byte[] encryptAsymmetricRsa(byte[] text) throws Exception {
		System.out.println("Encrypt Using Asymmetric Key");

		// Perform encryption and get the ciphertext
		CryptoKeyVersionName keyVersionName = getCryptoKeyVersionName();
		// Get the public key.
		PublicKey publicKey = kmsClient.getPublicKey(keyVersionName);

		// Convert the public PEM key to a DER key (see helper below).
		byte[] derKey = convertPemToDer(publicKey.getPem());
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derKey);

		// Generate RSA public key from DER
		RSAPublicKey rsaPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);

		CryptoKeyVersionAlgorithm algorithms = getCryptoKeyVersionAlgorithm();
		
		// Choose the appropriate OAEP padding algorithm based on the key size and hash
		String hashAlgorithm = getSHA(algorithms.name());
		// Initialize cipher with the correct transformation
		String transformation = "RSA/ECB/OAEPWith" + hashAlgorithm + "AndMGF1Padding";
		Cipher cipher = Cipher.getInstance(transformation);
		
		OAEPParameterSpec oaepParams = new OAEPParameterSpec(hashAlgorithm, "MGF1",
				new MGF1ParameterSpec(hashAlgorithm), PSource.PSpecified.DEFAULT);
		cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey, oaepParams);
		return cipher.doFinal(text);
	}


	/**
	 * Converts a base64-encoded PEM certificate like the one returned from Cloud
	 * KMS into a DER formatted certificate for use with the Java APIs.
	 * @param pem
	 * @return
	 */
	private byte[] convertPemToDer(String pem) {
		BufferedReader bufferedReader = new BufferedReader(new StringReader(pem));
		String encoded = bufferedReader.lines()
				.filter(line -> !line.startsWith("-----BEGIN") && !line.startsWith("-----END"))
				.collect(Collectors.joining());
		return Base64.getDecoder().decode(encoded);
	}

	/**
	 * Decrypt data using an asymmetric RSA private key
	 * @param ciphertext
	 * @return
	 * @throws Exception
	 */
	public byte[] decryptAsymmetricRsa(byte[] ciphertext) throws Exception {
		System.out.println("Decrypt Using Asymmetric Key");
		// Perform encryption and get the ciphertext
		CryptoKeyVersionName keyVersionName =getCryptoKeyVersionName();

		// Decrypt the ciphertext.
		AsymmetricDecryptResponse decryptedText = kmsClient.asymmetricDecrypt(keyVersionName,
				ByteString.copyFrom(ciphertext));

		// Convert the decrypted text back to String
		return decryptedText.getPlaintext().toByteArray();
	}

	public ByteString encryptSymmetric(String plaintext) throws Exception {
		System.out.println("Encrypt Using Symmetric Key");
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
		System.out.println("Decrypt Using Symmetric Key");
		// Decrypt the data
		DecryptRequest decryptRequest = DecryptRequest.newBuilder().setName(getFullName()).setCiphertext(ciphertext)
				.build();
		ByteString decryptedText = kmsClient.decrypt(decryptRequest).getPlaintext();

		// Convert the decrypted text back to String
		return decryptedText.toStringUtf8();
	}

	private String getFullName() {
		return String.format("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", sessionConfig.getProjectId(),
				sessionConfig.getLocation(), sessionConfig.getKeyRing(), sessionConfig.getKeyId());
	}

	public boolean isSymmetricKey() {
		// Fetch the key version (use the primary version of the key)
		CryptoKeyVersionAlgorithm algorithms = getCryptoKeyVersionAlgorithm();
		System.out.println("Encryption Algorith :::"+ algorithms.name());
			if (algorithms.name().contains("SYMMETRIC"))
				return true;
			
		return false;

	}
	
	   private String getSHA(String rsaAlgorithm) throws IllegalArgumentException {
	        String shaAlgorithm = rsaAlgorithmToSHA.get(rsaAlgorithm);
	        if (shaAlgorithm == null) {
	            throw new IllegalArgumentException("Unsupported RSA algorithm: " + rsaAlgorithm);
	        }
	        return shaAlgorithm;
	    }
	   
	private CryptoKeyVersionAlgorithm getCryptoKeyVersionAlgorithm() {
		CryptoKeyVersionName keyVersionName = getCryptoKeyVersionName();
		CryptoKeyVersion cryptoKeyVersion = kmsClient.getCryptoKeyVersion(keyVersionName);
		CryptoKeyVersionAlgorithm algorithms = cryptoKeyVersion.getAlgorithm();
		return algorithms;
	}

	private CryptoKeyVersionName getCryptoKeyVersionName() {
		CryptoKeyVersionName keyVersionName = CryptoKeyVersionName.of(sessionConfig.getProjectId(),
				sessionConfig.getLocation(), sessionConfig.getKeyRing(), sessionConfig.getKeyId(),
				sessionConfig.getKeyVersion());
		return keyVersionName;
	}
}
