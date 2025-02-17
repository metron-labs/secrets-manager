from logging import Logger
import os

from util_options import KMSClient
from .kms_client import GCPKMSClient
from .ksm_key_config import GCPKeyConfig

class GCPKeyValueStorage:
    
    default_config_file_location: str = "client-config.json"
    crypto_client: KMSClient
    config: dict[str, str] = {}
    last_saved_config_hash: str
    logger: Logger
    gcp_key_config: GCPKeyConfig
    key_type: str
    config_file_location: str
    gcp_session_config: GCPKMSClient
    is_asymmetric: bool = False
    
    
    def __init__(self, key_vault_config_file_location: str , gcp_key_config: GCPKeyConfig, gcp_session_config: GCPKMSClient, logger: Logger = None):
        self.config_file_location = key_vault_config_file_location or os.getenv('KSM_CONFIG_FILE') or self.default_config_file_location
        self.set_logger(logger)
        
        self.gcp_session_config = gcp_session_config
        self.gcp_key_config = gcp_key_config
        self.crypto_client = self.gcp_session_config.get_crypto_client()
        
        self.last_saved_config_hash = ""
        
    def set_logger(self, logger: Logger|None):
        if logger is not None:
            self.logger = logger
        else:
            logger = Logger("GCPKeyValueStorage")
            
            
    