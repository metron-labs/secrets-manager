import { EncryptionAlgorithmEnum } from "../enum";
import { MetadataBearer } from "@smithy/types";

export type DecryptResponse = {
  CiphertextForRecipient?: string;
  EncryptionAlgorithm: EncryptionAlgorithmEnum;
  KeyId: string;
  Plaintext: string;
  __metadata: MetadataBearer;
};
