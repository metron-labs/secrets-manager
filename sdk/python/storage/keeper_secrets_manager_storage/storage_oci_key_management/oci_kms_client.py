import logging
from .oci_session_config import OCISessionConfig

try:
    from oci.key_management import KmsCryptoClient
except ImportError:
    logging.getLogger().error("Missing OCI import dependencies."
                 " To install missing packages run: \r\n"
                 "pip install --upgrade \"oci\"\r\n")
    raise Exception("Missing import dependencies: oci")

class OciKmsClient:
    def __init__(self, session_config: OCISessionConfig):
        self.oci_kms_client = KmsCryptoClient(session_config.get_provider(), session_config.get_kms_endpoint())

    def get_crypto_client(self) -> KmsCryptoClient:
        return self.oci_kms_client
    