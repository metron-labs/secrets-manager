# GCP KSM
Keeper Secrets Manager integrates with GCP KMS in order to provide protection for Keeper Secrets Manager configuration files.  With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

## Features
* Encrypt and Decrypt your Keeper Secrets Manager configuration files with GCP KMS
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection.  Works with all Keeper Secrets Manager Python and Javascript SDK functionality

## Prerequisites
* Supports the JavaScript Secrets Manager SDK
* Requires `@google-cloud/kms` package
* These are permissions required for service account:
  * Cloud KMS CryptoKey Decrypter
  * Cloud KMS CryptoKey Encrypter
  * Cloud KMS CryptoKey Public Key Viewer

## Setup

1. Install KSM Storage Module

The Secrets Manager GCP KSM module can be installed using npm

> `npm install @keeper-security/secrets-manager-gcp`

2. Configure GCP Connection

By default the @google-cloud/kms library will utilize the default connection session setup with the GCP CLI with the gcloud auth command.  If you would like to specify the connection details, the two configuration files located at `~/.config/gcloud/configurations/config_default` and ~/.config/gcloud/legacy_credentials/<user>/adc.json can be manually edited.

See the GCP documentation for more information on setting up an GCP session: https://cloud.google.com/sdk/gcloud/reference/auth

Alternatively, configuration variables can be provided explicitly as a service account file using the GcpSessionConfig data class and providing  a path to the service account json file.

You will need a GCP service account to use the GCP KMS integration.

For more information on GCP service accounts see the GCP documentation: https://cloud.google.com/iam/docs/service-accounts

3. Add GCP KMS Storage to Your Code

Now that the GCP connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use GcpKmsKeyvalueStorage as your Secrets Manager storage in the SecretsManager constructor.

The storage will require a GCP Key ID, as well as the name of the Secrets Manager configuration file which will be encrypted by GCP KMS.
```
    import {GCPKeyValueStorage,GCPKeyConfig,GCPKSMClient} from "@keeper-security/secrets-manager-gcp";

    const getKeeperRecordsGCP = async () => {

        const keyConfig2  = new GCPKeyConfig("projects/keeper-integration-sample/locations/northamerica-northeast1/keyRings/Test_key/cryptoKeys/Test_symmetric/cryptoKeyVersions/1");
        const keyConfig = new GCPKeyConfig("projects/keeper-integration-sample/locations/northamerica-northeast1/keyRings/Test_key/cryptoKeys/asymmetric_decrypt_key_RSA/cryptoKeyVersions/1");
        console.log("extracted key details")
        const gcpSessionConfig = new GCPKSMClient().createClientFromCredentialsFile('/home/username1/Desktop/keeper_test/js/creds.json')
        console.log("extracted gcp session config")
        let config_path = "<path to client-config-gcp.json>"
         // oneTimeToken is used only once to initialize the storage
        // after the first run, subsequent calls will use ksm-config.txt
        const oneTimeToken = "US:kYKVGFJ2605-9UBF4VXd14AztMPXcxZ56zC9gr7O-Cw";
        
        const storage = await new GCPKeyValueStorage(config_path,keyConfig2,gcpSessionConfig).init();
        // await storage.changeKey(keyConfig2);
        await initializeStorage(storage, oneTimeToken);
        
        const {records} = await getSecrets({storage: storage});
        console.log(records)

        const firstRecord = records[0];
        const firstRecordPassword = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'bankAccount');
        console.log(firstRecordPassword.value[0]);
    }
    console.log("start")
    getKeeperRecordsGCP()

```

## Change Key operation and using default credentails from GCP
```
    import {GCPKeyValueStorage,GCPKeyConfig,GCPKSMClient} from "@keeper-security/secrets-manager-gcp";

    const getKeeperRecordsGCP = async () => {

        const keyConfig  = new GCPKeyConfig("projects/keeper-integration-sample/locations/northamerica-northeast1/keyRings/Test_key/cryptoKeys/Test_symmetric/cryptoKeyVersions/1");
        const keyConfig2  = new GCPKeyConfig("projects/keeper-integration-sample/locations/northamerica-northeast1/keyRings/Test_key/cryptoKeys/asymmetric_decrypt_key_RSA/cryptoKeyVersions/1");
        const gcpSessionConfig = new GCPKSMClient().createClientFromDefaultCredentials()
        let config_path = "/home/username1/Desktop/keeper_test/js/client-config-gcp.json"
         // oneTimeToken is used only once to initialize the storage
        // after the first run, subsequent calls will use ksm-config.txt
        const oneTimeToken = "US:kYKVGFJ2605-9UBF4VXd14AztMPXcxZ56zC9gr7O-Cw";
        
        const storage = await new GCPKeyValueStorage(config_path,keyConfig,gcpSessionConfig).init();
        await storage.changeKey(keyConfig2);
        await initializeStorage(storage, oneTimeToken);
        
        // Using token only to generate a config (for later usage)
        // requires at least one access operation to bind the token
        const {records} = await getSecrets({storage: storage});
        console.log(records)

        const firstRecord = records[0];
        const firstRecordPassword = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'bankAccount');
        console.log(firstRecordPassword.value[0]);
    }
    console.log("start")
    getKeeperRecordsGCP()
```

You're ready to use the KSM integration 👍
Using the GCP KMS Integration

Once setup, the Secrets Manager GCP KMS integration supports all Secrets Manager JavaScript SDK functionality. Your code will need to be able to access the GCP KMS APIs in order to manage the decryption of the configuration file when run.
