from google.cloud import kms
from google.oauth2 import service_account

class GCPKSMClient:
    """
    A client for interacting with Google Cloud KMS.
    """
    def __init__(self):
        """
        Initializes a GCP KMS client using the default configuration.
        
        By default, the GCP KMS client will use the Application Default Credentials (ADC)
        to authenticate.
        """
        self.kms_client = kms.KeyManagementServiceClient()

    def create_client_from_credentials_file(self, credentials_key_file_path: str):
        """
        Creates a new GCP KMS client using the specified credentials file.

        :param credentials_key_file_path: Path to the JSON key file containing
                                          the service account credentials.
        :return: The GCPKSMClient instance with the new client.
        """
        credentials = service_account.Credentials.from_service_account_file(credentials_key_file_path)
        self.kms_client = kms.KeyManagementServiceClient(credentials=credentials)
        return self

    def create_client_using_credentials(self, client_email: str, private_key: str):
        """
        Creates a new GCP KMS client using the specified client email and private key.

        :param client_email: The email address associated with the service account.
        :param private_key: The private key corresponding to the service account.
        :return: The GCPKSMClient instance with the new client.
        """
        credentials = service_account.Credentials.from_service_account_info({
            "type": "service_account",
            "client_email": client_email,
            "private_key": private_key,
        })
        self.kms_client = kms.KeyManagementServiceClient(credentials=credentials)
        return self

    def get_crypto_client(self):
        """
        Returns the KMS client instance.
        """
        return self.kms_client
