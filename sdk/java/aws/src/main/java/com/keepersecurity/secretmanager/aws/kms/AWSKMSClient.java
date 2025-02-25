package com.keepersecurity.secretmanager.aws.kms;

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

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;

public class AWSKMSClient {

	private KmsClient kmsClient;

	public AWSKMSClient(AwsSessionConfig sessionConfig) {
		AwsBasicCredentials awsCreds = AwsBasicCredentials.create(sessionConfig.getAwsAccessKeyId(),
				sessionConfig.getAwsSecretAccessKey());
		kmsClient = KmsClient.builder().credentialsProvider(StaticCredentialsProvider.create(awsCreds))
				.region(sessionConfig.getRegionName()).build();
	}
	
	public byte[] encrypt(SdkBytes message, String keyId) throws Exception {
		if (Constants.SYMMETRIC_DEFAULT.equals(getKeySpecType(keyId))) {
			return encryptSymmetric(message, keyId);
		}else {
			return encryptAsymmetric(message, keyId);
		}
	}

	public SdkBytes decrypt(byte[] ciphertext, String keyId) throws Exception {
		if (Constants.SYMMETRIC_DEFAULT.equals(getKeySpecType(keyId))) {
			return decryptSymmetric(ciphertext, keyId);
		}else {
			return decryptAsymmetric(ciphertext, keyId);
		}
	}
	
	private String getKeySpecType(String keyId) {
		return kmsClient.describeKey(DescribeKeyRequest.builder().keyId(keyId).build()).keyMetadata()
				.keySpecAsString();
	}
	
	public boolean isSymmetricKey(String keyId) {
		if (Constants.SYMMETRIC_DEFAULT.equals(getKeySpecType(keyId))) {
			return true;
		}
		return false;
	}
	
	private byte[] encryptSymmetric(SdkBytes message, String keyId) throws Exception {
		EncryptRequest encryptRequest = EncryptRequest.builder().keyId(keyId)
				.plaintext(message).build();
		EncryptResponse encryptResponse = kmsClient.encrypt(encryptRequest);
		return encryptResponse.ciphertextBlob().asByteArray();

	}

	private SdkBytes decryptSymmetric(byte[] ciphertext, String keyId) throws Exception {
		DecryptRequest decryptRequest = DecryptRequest.builder().keyId(keyId)
				.ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
				.build();
		DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);
		return decryptResponse.plaintext();
	}
	
	private byte[] encryptAsymmetric(SdkBytes message, String keyId) throws Exception {
		EncryptRequest encryptRequest = EncryptRequest.builder().keyId(keyId)
				.plaintext(message)
				.encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
				.build();
		EncryptResponse encryptResponse = kmsClient.encrypt(encryptRequest);
		return encryptResponse.ciphertextBlob().asByteArray();
	}
	private SdkBytes decryptAsymmetric(byte[] ciphertext, String keyId) throws Exception {
		DecryptRequest decryptRequest = DecryptRequest.builder().keyId(keyId)
				.ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
				.encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
				.build();
		DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);
		return decryptResponse.plaintext();
	}
}
