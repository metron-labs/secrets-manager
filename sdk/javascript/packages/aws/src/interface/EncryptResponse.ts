import { EncryptionAlgorithmEnum } from "../enum";

export type EncryptResponse = {
  CiphertextBlob: string;
  KeyId: string;
  EncryptionAlgorithm: EncryptionAlgorithmEnum;
};
