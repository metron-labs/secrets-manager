export enum EncryptionAlgorithmEnum {
    SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT",
    RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256",
    RSAES_OAEP_SHA_1 = "RSAES_OAEP_SHA_1",
    SM2PKE = "SM2PKE"
}

export enum AwsKeyType {
    SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT",
    RSA_2048 = "RSA_2048",
    RSA_4096 = "RSA_4096",
}

export enum KeySpecEnum {
    RSA_2048 = 'RSA_2048',
    RSA_3072 = 'RSA_3072',
    RSA_4096 = 'RSA_4096',
    ECC_NIST_P256 ='ECC_NIST_P256',
    ECC_NIST_P384 ='ECC_NIST_P384',
    ECC_NIST_P521 ='ECC_NIST_P521',
    ECC_SECG_P256K1 ='ECC_SECG_P256K1',
    SYMMETRIC_DEFAULT = 'SYMMETRIC_DEFAULT',
    HMAC_224 ='HMAC_224',
    HMAC_256='HMAC_256',
    HMAC_384='HMAC_384',
    HMAC_512='HMAC_512',
    SM2='SM2'
}

export enum KeyUsageEnum {
    SIGN_VERIFY = 'SIGN_VERIFY',
    ENCRYPT_DECRYPT = 'ENCRYPT_DECRYPT',
    GENERATE_VERIFY_MAC = 'GENERATE_VERIFY_MAC',
    KEY_AGREEMENT = 'KEY_AGREEMENT'
}

export enum KeyStateEnum {
    Creating = 'Creating',
    Enabled = 'Enabled',
    Disabled = 'Disabled',
    PendingDeletion = 'PendingDeletion',
    PendingImport = 'PendingImport',
    PendingReplicaDeletion = 'PendingReplicaDeletion',
    Unavailable = 'Unavailable',
    Updating = 'Updating'
}

export enum KeyOriginEnum {
    AWS_KMS = 'AWS_KMS',
    EXTERNAL = 'EXTERNAL',
    AWS_CLOUDHSM = 'AWS_CLOUDHSM',
    EXTERNAL_KEY_STORE = 'EXTERNAL_KEY_STORE'
}

export enum KeyManagerEnum {
    AWS = 'AWS',
    CUSTOMER = 'CUSTOMER'
}

export enum ExpirationModelEnum {
    KEY_MATERIAL_DOES_NOT_EXPIRE = 'KEY_MATERIAL_DOES_NOT_EXPIRE',
    KEY_MATERIAL_EXPIRES = 'KEY_MATERIAL_EXPIRES'
}

export enum SigningAlgorithmsEnum {
    RSASSA_PSS_SHA_256 = 'RSASSA_PSS_SHA_256',
    RSASSA_PSS_SHA_384='RSASSA_PSS_SHA_384',
    RSASSA_PSS_SHA_512='RSASSA_PSS_SHA_512',
    RSASSA_PKCS1_V1_5_SHA_256='RSASSA_PKCS1_V1_5_SHA_256',
    RSASSA_PKCS1_V1_5_SHA_384='RSASSA_PKCS1_V1_5_SHA_384',
    RSASSA_PKCS1_V1_5_SHA_512='RSASSA_PKCS1_V1_5_SHA_512',
    ECDSA_SHA_256='ECDSA_SHA_256',
    ECDSA_SHA_384='ECDSA_SHA_384',
    ECDSA_SHA_512='ECDSA_SHA_512',
    SM2DSA='SM2DSA',
}

export enum MultiRegionKeyTypeEnum {
    PRIMARY = 'PRIMARY',
    REPLICA = 'REPLICA'
}

export enum MacAlgorithmsEnum {
    HMAC_SHA_224 = 'HMAC_SHA_224',
    HMAC_SHA_256 = 'HMAC_SHA_256',
    HMAC_SHA_384 = 'HMAC_SHA_384',
    HMAC_SHA_512 = 'HMAC_SHA_512'
}