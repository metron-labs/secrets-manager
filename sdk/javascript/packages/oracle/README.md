# Oracle Key Management
Keeper Secrets Manager integrates with **Oracle Key Management Service (OCI KMS)** to provide protection for Keeper Secrets Manager configuration files. With this integration, you can secure connection details on your machine while leveraging Keeper's **zero-knowledge encryption** for all your secret credentials.

## Features
* Encrypt and decrypt your Keeper Secrets Manager configuration files using **OCI KMS**.
* Protect against unauthorized access to your **Secrets Manager connections**.
* Requires only minor code modifications for immediate protection. Works with all Keeper Secrets Manager J**avaScript SDK** functionality.

## Prerequisites
* Supports the JavaScript Secrets Manager SDK.
* Requires the oci-keymanagement package from OCI SDK.
* OCI KMS Key needs `ENCRYPT` and `DECRYPT` permissions.

## Setup

1. Install KSM Storage Module

The Secrets Manager oracle KSM module can be installed using npm

> `npm install @keeper-security/secrets-manager-oracle-kv`

2. Configure oracle Connection

By default, the oci-keymanagement library will use the **default OCI configuration file** (`~/.oci/config`).

See the (OCI documentation)[https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm] for more details.

1. Add oracle KMS Storage to Your Code

Now that the oracle connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use `OciKeyValueStorage` as your Secrets Manager storage in the SecretsManager constructor.

The storage will require an `Config file location`, `configuration profile`(if there are multiple profile configurations) and the OCI `KMS endpoint` as well as the name of the Secrets Manager configuration file which will be encrypted by Oracle KMS.
```
    import { OCISessionConfig, OciKeyValueStorage } from "@keeper-security/secrets-manager-oracle-kv";

    const getKeeperRecordsOCI = async () => {

        const configFileLocation = "/home/...../.oci/config";
        const profile = "DEFAULT";
        const kmsEndpoint = "https://<>-crypto.kms.<location>.oraclecloud.com";

        const ociSessionConfig = await new OCISessionConfig(configFileLocation, profile, kmsEndpoint);

        let config_path = "/home/metron/Desktop/keeper_test/js/client-config-oracle.json";

        // oneTimeToken is used only once to initialize the storage
        // after the first run, subsequent calls will use ksm-config.txt
        const oneTimeToken = "US:kYKVGFJ2605-9UBF4VXd14AztMPXcxZ56zC9gr7O-Cw";

        const keyId = 'ocid1.key.oc1.iad.<>.abuwcljrwhzx4ufz7ntyonykf5nk2e5lpfifabzikcipf6aq2ffqxgnpnjfa';
        const keyVersionId = "ocid1.keyversion.oc1.iad.<>.a4irm6l3bwyaa.abuwcljrfulolwiqbl4z67s42dgv3p44gg2gnqnoiznfrjvjqgna2y3yf6lq";

        const storage = await new OciKeyValueStorage(keyId, keyVersionId, config_path2, ociSessionConfig).init();
        // await storage.changeKey(keyId);
        await initializeStorage(storage, ott2);

        // Using token only to generate a config (for later usage)
        // requires at least one access operation to bind the token

        const { records } = await getSecrets({ storage: storage });
        console.log(records);

        const firstRecord = records[0];
        const firstRecordPassword = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'bankAccount');
        console.log(firstRecordPassword.value[0]);
    };
    console.log("start");
    getKeeperRecordsOCI();
```

Once set up, the Secrets Manager OCI KMS integration supports all Secrets Manager JavaScript SDK functionality.

Your code will need access to the OCI KMS APIs to manage encryption and decryption of the configuration file at runtime.

Let me know if you need further refinements! 🚀