***Azure Key Vault***

Protect Secrets Manager connection details with Azure Key Vault

Keeper Secrets Manager integrates with Azure Key Vault in order to provide protection for Keeper Secrets Manager configuration files.  With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.
Features

* Encrypt and Decrypt your Keeper Secrets Manager configuration files with Azure Key Vault
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection.  Works with all Keeper Secrets Manager Python SDK functionality

Prerequisites

* Supports the Java/Kotlin Secrets Manager SDK.
* Requires Azure packages: azure-identity and azure-keyvault-keys.
* Works with just RSA key types with `WrapKey` and `UnWrapKey` permissions.

1. Configure Azure Connection

configuration variables can be provided as 

```
    import com.keepersecurity.secretsManager.core.KeyValueStorage;
    import com.keepersecurity.secretmanager.azurekv.AzureSessionConfig;
    import com.keepersecurity.secretmanager.azurekv.AzureKeyValueStorage;
    
    String tenant_id="<Tenant ID>" 
    String client_id="<Client ID>"
    String client_secret="<Client Secret>"
    String azure_keyvault_url="<Azure Key Vault URL>"
    AzureSessionConfig azureSessionConfig = new AzureSessionConfig(tenant_id, client_id, client_secret, azure_keyvault_url)
```

An access key using the `AzureSessionConfig` data class and providing  `tenant_id` , `client_id` ,  `client_secret` and `azure_keyvault_url`variables.

You will need an Azure App directory App to use the Azure Key Vault integration.


For more information on Azure App Directory App registration and Permissions see the Azure documentation: https://learn.microsoft.com/en-us/azure/key-vault/general/authentication

2. Add Azure Key Vault Storage to Your Code

Now that the Azure connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use AzureKeyValueStorage as your Secrets Manager storage in the SecretsManager constructor.

The storage will require an Azure Key ID, as well as the name of the Secrets Manager configuration file which will be encrypted by Azure Key Vault.

```
		import com.keepersecurity.secretmanager.azurekv.AzureSessionConfig;
		import com.keepersecurity.secretmanager.azurekv.AzureKeyValueStorage;
		import com.keepersecurity.secretsManager.core.KeyValueStorage;
		import com.keepersecurity.secretsManager.core.SecretsManagerOptions;

	    String configFileLocation = "<KSM-Config.json>";
	    String keyId = "<Azure RSA Key>";
		try{
	  		KeyValueStorage STORAGE =  AzureKeyValueStorage.getInternalStorage(keyId, configFileLocation, azureSessionConfig);
			Security.addProvider(BouncyCastleFipsProvider())
			SecretsManagerOptions OPTIONS = new SecretsManagerOptions(STORAGE);
	    	 //getSecrets(OPTIONS)
		}catch (Exception e) {
  			  System.out.println(e.getMessage());
 		}
			
```
