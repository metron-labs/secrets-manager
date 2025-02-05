import { KMSClient, EncryptionAlgorithmSpec } from "@aws-sdk/client-kms";

export type EncryptBufferOptions = {
  keyId: string;
  encryptionAlgorithm: EncryptionAlgorithmSpec;
  message: string;
  cryptoClient: KMSClient;
  keyType: string;
};

export type DecryptBufferOptions = {
  keyId: string;
  encryptionAlgorithm: EncryptionAlgorithmSpec;
  ciphertext: Buffer;
  cryptoClient: KMSClient;
  keyType: string;
};
