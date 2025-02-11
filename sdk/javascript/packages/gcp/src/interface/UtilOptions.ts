import { KeyManagementServiceClient } from '@google-cloud/kms';
import { GCPKeyConfig } from 'src/GcpKeyConfig';

export type KMSClient = InstanceType <typeof KeyManagementServiceClient> ;

export type EncryptBufferOptions = {
  isAsymmetric: boolean;
  message: string;
  cryptoClient: KMSClient;
  keyType: string;
  keyProperties : GCPKeyConfig
};

export type DecryptBufferOptions = {
  isAsymmetric: boolean;
  ciphertext: Buffer;
  cryptoClient: KMSClient;
  keyType: string;
  keyProperties : GCPKeyConfig
};

export type encryptOptions = {
  message: Buffer;
  cryptoClient: KMSClient;
  keyProperties : GCPKeyConfig;
  isAsymmetric: boolean;
};

export type decryptOptions = {
  cipherText: Buffer;
  cryptoClient: KMSClient;
  keyProperties : GCPKeyConfig;
  isAsymmetric: boolean;
};