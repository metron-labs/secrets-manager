***Azure Key Vault***

Protect Secrets Manager connection details with Azure Key Vault

Keeper Secrets Manager integrates with Azure Key Vault in order to provide protection for Keeper Secrets Manager configuration files.  With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.
Features

* Encrypt and Decrypt your Keeper Secrets Manager configuration files with Azure Key Vault
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection.  Works with all Keeper Secrets Manager Python SDK functionality

Prerequisites

* Supports the Python and Javascript Secrets Manager SDK.
* Requires Azure packages: azure-identity and azure-keyvault-keys.
* Works with just RSA key types with `WrapKey` and `UnWrapKey` permissions.

Setup
1. Install KSM Storage Module

The Secrets Manager azure modules are located in the Keeper Secrets Manager storage module which can be installed using npm

> `npm install @keeper-security/secrets-manager-azure`

1. Configure Azure Connection

configuration variables can be provided as 

```
    import {AzureSessionConfig} from "@keeper-security/secrets-manager-azure";
    const tenant_id="<Some Tenant ID>" 
    const client_id="<Some Client ID>"
    const client_secret="<Some Client Secret>"

    const azureSessionConfig = new AzureSessionConfig(tenant_id, client_id, client_secret)
```

An access key using the `AzureSessionConfig` data class and providing  `tenant_id` , `client_id` and  `client_secret` variables.

You will need an Azure App directory App to use the Azure Key Vault integration.


For more information on Azure App Directory App registration and Permissions see the Azure documentation: https://learn.microsoft.com/en-us/azure/key-vault/general/authentication

1. Add Azure Key Vault Storage to Your Code

Now that the Azure connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use AzureKeyValueStorage as your Secrets Manager storage in the SecretsManager constructor.

The storage will require an Azure Key ID, as well as the name of the Secrets Manager configuration file which will be encrypted by Azure Key Vault.

```
    import { getSecrets, initializeStorage, localConfigStorage } from '@keeper-security/secrets-manager-core';
    import {AzureKeyValueStorage, AzureSessionConfig} from "@keeper/secrets-manager-azure";

    const getKeeperRecords = async () => {

        const tenant_id="<tenant_id>" 
        const client_id="<client_id>"
        const client_secret="<client-secret>"
        const azureSessionConfig = new AzureSessionConfig(tenant_id, client_id, client_secret)
        
        let config_path = "/home/metron/Desktop/keeper_test/js/client-config.json"
            
        // oneTimeToken is used only once to initialize the storage
        // after the first run, subsequent calls will use ksm-config.txt
        const oneTimeToken = "US:kYKVGFJ2605-9UBF4VXd14AztMPXcxZ56zC9gr7O-Cw";
        
        const keyId = 'https://keeper-integration1-kv.vault.azure.net/keys/azure-kv-test-rsa/<version>'
        const storage = await new AzureKeyValueStorage(keyId,config_path,azureSessionConfig).init();
        await initializeStorage(storage, oneTimeToken);
        
        const {records} = await getSecrets({storage: storage});
        console.log(records)

        const firstRecord = records[0];
        const firstRecordPassword = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'bankAccount');
        console.log(firstRecordPassword.value[0]);
    }
    getKeeperRecords()
```

You're ready to use the KSM integration 👍
Using the Azure Key Vault Integration

Once setup, the Secrets Manager Azure Key Vault integration supports all Secrets Manager Python SDK functionality.  Your code will need to be able to access the Azure Key Vault APIs in order to manage the decryption of the configuration file when run. 

### Change Key used to encrypt the configuration file
```
    import { getSecrets, initializeStorage, localConfigStorage } from '@keeper-security/secrets-manager-core';
    import {AzureKeyValueStorage, AzureSessionConfig} from "@keeper/secrets-manager-azure";

    const getKeeperRecords = async () => {

        const tenant_id="<tenant_id>" 
        const client_id="<client_id>"
        const client_secret="<client-secret>"
        const azureSessionConfig = new AzureSessionConfig(tenant_id, client_id, client_secret)
        
        let config_path = "/home/metron/Desktop/keeper_test/js/client-config.json"
        
        // oneTimeToken is used only once to initialize the storage
        // after the first run, subsequent calls will use ksm-config.txt
        const oneTimeToken = "US:kYKVGFJ2605-9UBF4VXd14AztMPXcxZ56zC9gr7O-Cw";
        
        const keyId = 'https://keeper-integration1-kv.vault.azure.net/keys/azure-kv-test-rsa/<version>'
        const keyId2 = "https://keeper-integration1-kv.vault.azure.net/keys/keeper-test-rsa-2/<version>"
        const storage = await new AzureKeyValueStorage(keyId2,config_path,azureSessionConfig).init();
        await storage.changeKey(keyId2);
        await initializeStorage(storage, oneTimeToken);
        
        const {records} = await getSecrets({storage: storage});
        console.log(records)

        const firstRecord = records[0];
        const firstRecordPassword = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'bankAccount');
        console.log(firstRecordPassword.value[0]);
    }
    console.log("start")
    getKeeperRecords()
```

### using custom logging if needed
The module interfaces well with custom logging functionalities your program may have. If no logger is provided then console is chosen as default. Here is an example with `winston` logging framework

```
    import { getSecrets, initializeStorage, localConfigStorage } from '@keeper-security/secrets-manager-core';
    import {AzureKeyValueStorage, AzureSessionConfig,Logger} from "@keeper/secrets-manager-azure";
    import winston from "winston";

    class WinstonLogger implements Logger {
        private logger: winston.Logger;

        constructor() {
            this.logger = winston.createLogger({
                level: "info",
                format: winston.format.combine(
                    winston.format.timestamp(),
                    winston.format.printf(({ level, message, timestamp }) => {
                        return `${timestamp} | ${level.toUpperCase()} | ${message}`;
                    })
                ),
                transports: [new winston.transports.Console()]
            });
        }

        info(message: string, ...meta: any[]): void {
            this.logger.info(message, ...meta);
        }

        warn(message: string, ...meta: any[]): void {
            this.logger.warn(message, ...meta);
        }

        error(message: string, ...meta: any[]): void {
            this.logger.error(message, ...meta);
        }

        debug(message: string, ...meta: any[]): void {
            this.logger.debug?.(message, ...meta);
        }
    }

    const getKeeperRecords = async () => {

        const tenant_id="<tenant_id>" 
        const client_id="<client_id>"
        const client_secret="<client-secret>"
        const azureSessionConfig = new AzureSessionConfig(tenant_id, client_id, client_secret)

        
        let config_path = "/home/metron/Desktop/keeper_test/js/client-config.json"
        let globalLogger = new WinstonLogger(); // one way to create a logger which intefraces perfectly with this integration
        let globalLogger2 = winston.createLogger({transports: [new winston.transports.Console()]}); //second way to create a logger instance
        
        // oneTimeToken is used only once to initialize the storage
        // after the first run, subsequent calls will use ksm-config.txt
        const oneTimeToken = "US:kYKVGFJ2605-9UBF4VXd14AztMPXcxZ56zC9gr7O-Cw";
        
        const keyId = 'https://keeper-integration-kv.vault.azure.net/keys/azure-kv-test-rsa/<version>'
        const keyId2 = "https://keeper-integration-kv.vault.azure.net/keys/keeper-test-rsa-2/<version>"
        const storage = await new AzureKeyValueStorage(keyId2,config_path,azureSessionConfig,globalLogger).init();
        // await storage.changeKey(keyId);
        await initializeStorage(storage, oneTimeToken);
        
        // Using token only to generate a config (for later usage)
        // requires at least one access operation to bind the token
        //await getSecrets({storage: storage})
        
        const {records} = await getSecrets({storage: storage});
        console.log(records)

        const firstRecord = records[0];
        const firstRecordPassword = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'bankAccount');
        console.log(firstRecordPassword.value[0]);
    }
    console.log("start")
    getKeeperRecords()
```
