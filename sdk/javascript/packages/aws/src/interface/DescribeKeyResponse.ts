import { Sign } from "crypto";
import {  EncryptionAlgorithmEnum, ExpirationModelEnum, KeyManagerEnum, KeyOriginEnum, KeySpecEnum, KeyStateEnum, KeyUsageEnum, MacAlgorithmsEnum, MultiRegionKeyTypeEnum, SigningAlgorithmsEnum } from "../enum";

export type DescribeKeyResponse = {
    'KeyMetadata': {
        'AWSAccountId': string,
        'KeyId': string,
        'Arn': string,
        'CreationDate': Date,
        'Enabled': boolean,
        'Description': string,
        'KeyUsage': KeyUsageEnum,
        'KeyState': KeyStateEnum,
        'DeletionDate': Date,
        'ValidTo': Date,
        'Origin': KeyOriginEnum,
        'CustomKeyStoreId': string,
        'CloudHsmClusterId': string,
        'ExpirationModel': ExpirationModelEnum,
        'KeyManager': KeyManagerEnum,
        'CustomerMasterKeySpec': KeySpecEnum,
        'KeySpec': KeySpecEnum,
        'EncryptionAlgorithms': 
            EncryptionAlgorithmEnum[]
        ,
        'SigningAlgorithms': SigningAlgorithmsEnum[],
        'KeyAgreementAlgorithms': string[],
        'MultiRegion': boolean,
        'MultiRegionConfiguration': {
            'MultiRegionKeyType': MultiRegionKeyTypeEnum,
            'PrimaryKey': {
                'Arn': string,
                'Region': string
            },
            'ReplicaKeys': [
                {
                    'Arn': string,
                    'Region': string
                },
            ]
        },
        'PendingDeletionWindowInDays': number,
        'MacAlgorithms': MacAlgorithmsEnum[],
        'XksKeyConfiguration': {
            'Id': string
        }
    }
}