import { EncryptionAlgorithmEnum } from "../enum";

export type DecryptResponse = {
    CiphertextForRecipient ?: string,
    EncryptionAlgorithm : EncryptionAlgorithmEnum
    KeyId : string
    Plaintext : string
}